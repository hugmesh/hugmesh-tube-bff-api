package systems.snapdragon.tubebff.google;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;

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

    @Operation(operationId = "googleConnectStatus",
            summary = "The current user's Google connection status (display-safe; never "
            + "exposes the refresh token). Use-gated + owner-scoped.")
    @GetMapping("/status")
    public Mono<TubeGoogleDto.ConnectStatus> status(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.fromCallable(() -> owner.resolve(auth)))
                .flatMap(o -> links.findLive(o.domain(), o.subject())
                        .map(TubeGoogleDto.ConnectStatus::of)
                        .defaultIfEmpty(new TubeGoogleDto.ConnectStatus(
                                false, null, null, null, false)));
    }

    @Operation(operationId = "googleAuthorizeUrl",
            summary = "Build the Google consent URL (access_type=offline&prompt=consent "
            + "for a refresh token) with a signed CSRF state binding this principal. "
            + "Use-gated + owner-scoped.")
    @GetMapping("/authorize")
    public Mono<TubeGoogleDto.AuthorizeUrl> authorize(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.authorizeUrl(auth)))   // gated: not invoked until use is allowed
                .map(TubeGoogleDto.AuthorizeUrl::new);
    }

    @Operation(operationId = "googleConnectCallback",
            summary = "Google's OAuth redirect target: verify the signed state, exchange "
            + "the code, AES-256-GCM-encrypt + store the refresh token. The state binds the "
            + "principal (the callback hop carries no bearer of its own). Use-gated + owner-scoped.")
    @GetMapping("/callback")
    public Mono<ResponseEntity<TubeGoogleDto.ConnectStatus>> callback(
            @RequestParam("code") String code, @RequestParam("state") String state,
            Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.callback(code, state, auth)))   // gated
                .map(link -> ResponseEntity.ok(TubeGoogleDto.ConnectStatus.of(link)));
    }

    @Operation(operationId = "googleDisconnect",
            summary = "Disconnect: best-effort revoke the token at Google, then "
            + "soft-revoke the connection (audit-retained). Use-gated + owner-scoped.")
    @PostMapping("/disconnect")
    public Mono<ResponseEntity<TubeGoogleDto.ConnectStatus>> disconnect(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> connect.disconnect(auth)))   // gated
                .thenReturn(ResponseEntity.ok(new TubeGoogleDto.ConnectStatus(
                        false, null, null, null, false)));
    }
}
