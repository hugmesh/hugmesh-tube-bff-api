package systems.hugmesh.tubebff.google;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.tubebff.access.TubeAccessGuard;

/**
 * The Google (youtube.readonly) CONNECT surface — {@code /bff/tube/google-connect/**}.
 * A user connects their own Google account so this BFF can sync their YouTube
 * subscriptions; this is SEPARATE from the Casdoor sign-in.
 *
 * <p><b>Two gates on every method (defence in depth):</b>
 * <ol>
 *   <li>{@link TubeAccessGuard#assertCanUse} — the DEFAULT-DENY use overlay: a principal
 *       may touch the tube feature ONLY with an active {@code tube_access} use grant (and
 *       no active ban), SUPERADMIN exempt. The bare {@code ROLE_TUBE} floor (the
 *       SecurityConfig path gate) does NOT by itself confer use.</li>
 *   <li>OWNER-SCOPE — the acting subject + brand are derived SERVER-SIDE from the
 *       validated JWT ({@link PersonalOwner}); the service keys every read/write on
 *       {@code (subject, domain)} so a user only ever touches THEIR OWN connection. There
 *       is no user-supplied owner/domain to forge, and the domain FAILS CLOSED if
 *       unresolved (no SUPERADMIN cross-brand bypass for a personal connect).</li>
 * </ol>
 *
 * <p><b>The callback's principal binding.</b> Google's redirect to {@code /callback} is a
 * browser navigation that does NOT carry the user's bearer token. The acting principal is
 * therefore bound by the SIGNED {@code state} ({@link GoogleConnectState}) minted at
 * {@code /authorize} — it carries the subject + brand under an HMAC. In this BFF the
 * fe-gateway fronts {@code /bff/**} and attaches the session bearer even on the redirect
 * hop, so {@code authorize} and {@code callback} both run with the JWT; we keep the
 * use-gate + owner-resolve on the callback AND verify the signed state against that
 * resolved principal, so the two MUST agree (the state is the authoritative binder, the
 * bearer is the second factor). If a deployment ever routes the raw Google redirect
 * straight here without a bearer, the signed state still carries the subject+brand to
 * re-establish the principal — the state, not the (possibly absent) bearer, is what binds
 * the connection to an owner.
 */
@Tag(name = "Tube Google Connect", description = "Connect/callback/disconnect a user's "
        + "Google (youtube.readonly) account. Gated by the tube_access use overlay "
        + "(TubeAccessGuard) + owner-scope (server-derived subject+brand, fail-closed). "
        + "The refresh token is AES-256-GCM-encrypted at rest and NEVER returned.")
@RestController
@RequestMapping("/bff/tube/google-connect")
public class GoogleConnectController {

    /** The authenticated floor, matching the sibling {@code TubeDownloadController} /
     *  {@code TubeMediaController} defence-in-depth pattern. The exact use decision (an
     *  active grant AND NOT an active ban, SUPERADMIN exempt) is enforced programmatically
     *  by {@link TubeAccessGuard#assertCanUse} in each handler — a static SpEL cannot
     *  consult the DB for a per-principal grant/ban. */
    private static final String AUTHENTICATED = "isAuthenticated()";

    private final TubeAccessGuard useGate;
    private final GoogleConnectService connect;
    private final TubeGoogleLinkRepository links;
    private final PersonalOwner owner;

    public GoogleConnectController(TubeAccessGuard useGate, GoogleConnectService connect,
                                   TubeGoogleLinkRepository links, PersonalOwner owner) {
        this.useGate = useGate;
        this.connect = connect;
        this.links = links;
        this.owner = owner;
    }

    /**
     * Returns the current user's Google connection status — display-safe metadata only
     * (email, scopes, connected-at, reauth flag). The refresh token is never included.
     *
     * @param auth the authenticated principal
     * @return a {@code Mono} emitting the {@link TubeGoogleDto.ConnectStatus}; {@code
     *         connected=false} when no live link exists
     */
    @Operation(operationId = "googleConnectStatus",
            summary = "The current user's Google connection status (display-safe; never "
            + "exposes the refresh token). Use-gated + owner-scoped.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Connection status (connected or not)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "No active tube_access grant, active ban, or brand unresolvable"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @GetMapping("/status")
    public Mono<TubeGoogleDto.ConnectStatus> status(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.fromCallable(() -> owner.resolve(auth)))
                .flatMap(o -> links.findLive(o.domain(), o.subject())
                        .map(TubeGoogleDto.ConnectStatus::of)
                        .defaultIfEmpty(new TubeGoogleDto.ConnectStatus(
                                false, null, null, null, false)));
    }

    /**
     * Build the Google OAuth consent URL. Carries {@code access_type=offline&prompt=consent}
     * (to obtain a refresh token) and an HMAC-signed {@code state} binding this
     * principal's subject + brand as the CSRF token and callback binder.
     *
     * @param auth the authenticated principal
     * @return a {@code Mono} emitting the {@link TubeGoogleDto.AuthorizeUrl} for the UI
     *         to redirect the user to
     */
    @Operation(operationId = "googleAuthorizeUrl",
            summary = "Build the Google consent URL (access_type=offline&prompt=consent "
            + "for a refresh token) with a signed CSRF state binding this principal. "
            + "Use-gated + owner-scoped.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "The Google consent URL"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "No active tube_access grant or brand unresolvable"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @GetMapping("/authorize")
    public Mono<TubeGoogleDto.AuthorizeUrl> authorize(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.authorizeUrl(auth)))   // gated: not invoked until use is allowed
                .map(TubeGoogleDto.AuthorizeUrl::new);
    }

    /**
     * Google's OAuth redirect target. Verifies the HMAC-signed {@code state} against the
     * resolved principal (CSRF check + principal binding), exchanges the {@code code} for
     * tokens, AES-256-GCM-encrypts the refresh token, soft-revokes any prior live link,
     * and inserts a fresh link row. A tampered/expired/cross-principal state is rejected
     * before any code exchange.
     *
     * @param code  the authorization code from Google's redirect query string
     * @param state the signed state value (HMAC-SHA256; minted by {@code /authorize})
     * @param auth  the authenticated principal (bearer-attached by the BFF gateway)
     * @return a {@code Mono} emitting 200 with the new {@link TubeGoogleDto.ConnectStatus}
     */
    @Operation(operationId = "googleConnectCallback",
            summary = "Google's OAuth redirect target: verify the signed state, exchange "
            + "the code, AES-256-GCM-encrypt + store the refresh token. The state binds the "
            + "principal (the callback hop carries no bearer of its own). Use-gated + owner-scoped.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Connection established; display-safe status returned"),
        @ApiResponse(responseCode = "400", description = "Missing or blank authorization code"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Invalid/expired/cross-principal state, or no active tube_access grant"),
        @ApiResponse(responseCode = "502", description = "Google token exchange failed"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @GetMapping("/callback")
    public Mono<ResponseEntity<TubeGoogleDto.ConnectStatus>> callback(
            @RequestParam("code") String code, @RequestParam("state") String state,
            Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.callback(code, state, auth)))   // gated
                .map(link -> ResponseEntity.ok(TubeGoogleDto.ConnectStatus.of(link)));
    }

    /**
     * Disconnect the current user's Google account. Best-effort revokes the stored refresh
     * token at Google (decrypted in memory only), then soft-revokes the link row (the row
     * is retained for audit, never hard-deleted). Idempotent — a no-op when there is no
     * live link. Always returns {@code connected=false}.
     *
     * @param auth the authenticated principal
     * @return a {@code Mono} emitting 200 with {@code connected=false}
     */
    @Operation(operationId = "googleDisconnect",
            summary = "Disconnect: best-effort revoke the token at Google, then "
            + "soft-revoke the connection (audit-retained). Use-gated + owner-scoped.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Disconnected (or was already disconnected)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "No active tube_access grant or brand unresolvable"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @PostMapping("/disconnect")
    public Mono<ResponseEntity<TubeGoogleDto.ConnectStatus>> disconnect(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.disconnect(auth)))   // gated
                .thenReturn(ResponseEntity.ok(new TubeGoogleDto.ConnectStatus(
                        false, null, null, null, false)));
    }
}
