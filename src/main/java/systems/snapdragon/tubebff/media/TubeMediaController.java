package systems.snapdragon.tubebff.media;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;
import systems.snapdragon.commons.security.Roles;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;
import java.util.regex.Pattern;

/**
 * The media URL signing surface — generates short-TTL HMAC-signed URLs that authorise
 * a specific user to stream a specific piece of content from the tube-media Nginx
 * sidecar.
 *
 * <p><b>DEFAULT-DENY use gate (first wall).</b> Before any path handling, {@code sign()}
 * invokes {@link TubeAccessGuard#assertCanUse} — exactly as
 * {@link systems.snapdragon.tubebff.download.TubeDownloadController},
 * {@link systems.snapdragon.tubebff.google.TubeSubscriptionsController}, and
 * {@link systems.snapdragon.tubebff.google.GoogleConnectController} do. The bare
 * {@code ROLE_TUBE} floor does NOT confer use: a banned / timed-out / never-granted
 * principal is 403'd here, so the ban/timeout that already blocks downloads and
 * subscriptions ALSO blocks the viewing capability (obtaining a signed media URL). Only
 * an active {@code tube_access} use grant (or the SUPERADMIN infra exemption inside the
 * guard) gets past this gate.
 *
 * <p><b>Two-wall owner check.</b>
 * <ol>
 *   <li><em>Wall 1 (gateway)</em> — the fe-gateway route-access gate: only principals
 *       holding {@code ROLE_TUBE} can reach {@code /bff/tube/**} at all.</li>
 *   <li><em>Wall 2 (this controller)</em> — the path must embed the calling user's own
 *       {@code /<domain>/<subject>/} prefix. A path that embeds a different user or a
 *       different brand is rejected 403 here — so user A can never obtain a signed URL
 *       for user B's content.</li>
 * </ol>
 *
 * <p><b>Path safety.</b> The path is validated against a strict allowlist pattern
 * ({@link #PATH_PATTERN}) that excludes {@code ..}, {@code //}, and any non-word
 * character beyond {@code /}, {@code .}, and {@code -}. A path that does not match is
 * rejected 400 so path traversal attempts never reach the signing step.
 *
 * <p><b>Route.</b> Mounted under {@code /bff/tube/media/**} — {@code /sign} sits inside the
 * {@code .authenticated()} floor declared in
 * {@link systems.snapdragon.tubebff.config.SecurityConfig} (the method-level
 * {@code @PreAuthorize("isAuthenticated()")} is defence-in-depth). The ONE exception is
 * {@code /verify}, which {@code SecurityConfig} marks {@code permitAll}: it is the
 * tube-media nginx sidecar's {@code auth_request} target and carries no JWT — the HMAC
 * signature minted by {@code /sign} is its sole credential.
 */
@Tag(name = "Tube Media Signing",
        description = "Short-TTL HMAC-signed media URLs for the tube-media Nginx sidecar. "
                + "Owner two-wall: ROLE_TUBE at gateway (wall 1) + path owner==jwt.subject "
                + "(wall 2). Signed URL binds user, domain, path, and expiry; TTL = 5 min.")
@RestController
@RequestMapping("/bff/tube/media")
public class TubeMediaController {

    /**
     * The authenticated floor for the media signing surface.
     * Wall 1 (ROLE_TUBE) is enforced by the gateway; wall 2 (owner check) is in the handler body.
     */
    private static final String AUTHENTICATED = "isAuthenticated()";

    /**
     * Allowlist pattern for path segments.
     *
     * <p>Rules enforced:
     * <ul>
     *   <li>Each segment matches [a-zA-Z0-9._-]+ (no special characters, no empty segments,
     *       no dot-dot sequences).</li>
     *   <li>Negative lookaheads reject // (two adjacent slashes) and .. (dot-dot traversal)
     *       anywhere in the string as belt-and-suspenders on top of the character class.</li>
     *   <li>The path must have at least three segments: /domain/subject/rest...
     *       Paths with only one or two segments are rejected as malformed.</li>
     * </ul>
     */
    private static final Pattern PATH_PATTERN = Pattern.compile(
            "^(?!.*//)(?!.*\\.\\.)((/[a-zA-Z0-9._-]+){2})(/[a-zA-Z0-9._-]+)+$");

    private final TubeMediaTokenService tokenService;

    /** The DEFAULT-DENY use overlay gate. Signing a media URL is a USE of the tube service,
     *  so it is gated by the same grant/ban/timeout overlay as downloads, subscriptions, and
     *  the Google connect flow — the bare {@code ROLE_TUBE} floor does not substitute for a
     *  grant. The exact decision (an active use grant AND NOT an active ban, SUPERADMIN
     *  exempt) is enforced programmatically by {@link TubeAccessGuard#assertCanUse} because a
     *  static {@code @PreAuthorize} cannot consult the DB for a per-principal grant/ban. */
    private final TubeAccessGuard useGate;

    public TubeMediaController(TubeMediaTokenService tokenService, TubeAccessGuard useGate) {
        this.tokenService = tokenService;
        this.useGate = useGate;
    }

    /**
     * Sign a short-TTL media access URL.
     *
     * <p>Returns {@code {"url": "/tube/content/<path>?sig=...&exp=...&sub=...&domain=...",
     * "expiresAt": "<ISO-8601>"}} on success.
     *
     * <p>Error responses:
     * <ul>
     *   <li>{@code 403} — the principal has no active {@code tube_access} use grant, or is
     *       under an active ban/timeout (the DEFAULT-DENY use gate, enforced FIRST).</li>
     *   <li>{@code 400} — path does not match the allowlist pattern (includes path
     *       traversal attempts or malformed paths).</li>
     *   <li>{@code 403} — the path's embedded domain or subject does not match the
     *       calling principal's JWT domain / subject (cross-user/cross-brand attempt).</li>
     * </ul>
     *
     * @param path the content path to sign, e.g. {@code /acme/alice/videos/vid.mp4}
     * @param auth the Spring Security authentication carrying the JWT
     */
    @Operation(operationId = "signMediaUrl",
            summary = "Sign a short-TTL (5 min) media URL for the calling user's own content. "
            + "Default-deny use (TubeAccessGuard) enforced first. "
            + "Path must start with /<domain>/<subject>/. Returns signed URL + expiresAt. "
            + "403 if no use grant / banned; 403 if path owner != jwt.subject; 400 if path is malformed.")
    @PreAuthorize(AUTHENTICATED)
    @GetMapping("/sign")
    public Mono<ResponseEntity<TubeMediaDto.SignedUrl>> sign(
            @RequestParam String path, Authentication auth) {
        // ── DEFAULT-DENY use gate (first wall) ────────────────────────────────
        // Signing a media URL is a USE of the tube service. Gate it with the same
        // grant/ban/timeout overlay as downloads/subscriptions/connect BEFORE any path or
        // owner handling — a banned/timed-out/never-granted ROLE_TUBE principal must NOT be
        // able to mint a signed URL even for their own content. The path/owner walls below
        // are not invoked until the gate completes (Mono.defer).
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> signGranted(path, auth)));
    }

    /** 200 (allow) for the nginx auth_request subrequest — empty body. */
    private static final Mono<ResponseEntity<Void>> ALLOW =
            Mono.just(ResponseEntity.ok().<Void>build());
    /** 403 (deny) for the nginx auth_request subrequest — empty, non-leaking body. */
    private static final Mono<ResponseEntity<Void>> DENY =
            Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<Void>build());

    /**
     * Verify a signed media URL — the {@code auth_request} target for the tube-media
     * nginx serving sidecar.
     *
     * <p><b>PUBLIC by design.</b> This is the one route under {@code /bff/tube/media/**}
     * that {@link systems.snapdragon.tubebff.config.SecurityConfig} marks {@code permitAll}:
     * the sidecar's internal {@code auth_request} subrequest carries NO user bearer, so the
     * short-TTL HMAC signature minted by {@link #sign} IS the credential. The default-deny
     * use gate and the owner two-wall were already enforced at SIGN time; here we only
     * re-check that the signature is authentic and unexpired for the exact
     * {@code (sub, domain, path, exp)} tuple it was minted over.
     *
     * <p><b>Fail-closed + non-leaking.</b> A missing/blank parameter, an unparseable
     * {@code exp}, an expired token, or a bad signature ALL return {@code 403} with an empty
     * body; only a valid, unexpired signature returns {@code 200}. nginx {@code auth_request}
     * treats {@code 2xx} as allow and everything else as deny, so a single 403 for every
     * failure mode keeps this from becoming an oracle.
     *
     * <p><b>Constant-time.</b> The HMAC comparison is constant-time
     * ({@link TubeMediaTokenService#verify} → {@code MessageDigest.isEqual}).
     *
     * @param path   the content path that was signed (e.g. {@code /acme/alice/videos/vid.mp4})
     * @param sig    the {@code sig} query parameter (base64url HMAC)
     * @param exp    the {@code exp} query parameter (epoch millis)
     * @param sub    the {@code sub} query parameter (owner subject the token was bound to)
     * @param domain the {@code domain} query parameter (brand the token was bound to)
     */
    @Operation(operationId = "verifyMediaUrl",
            summary = "Verify a signed media URL for the tube-media nginx sidecar's auth_request. "
            + "PUBLIC — no JWT (the HMAC signature is the credential). 200 if the signature is "
            + "valid AND unexpired for (sub, domain, path, exp); 403 (empty body) otherwise. "
            + "Fail-closed and non-leaking on any missing/malformed parameter.")
    @GetMapping("/verify")
    public Mono<ResponseEntity<Void>> verify(
            @RequestParam(required = false) String path,
            @RequestParam(required = false) String sig,
            @RequestParam(required = false) String exp,
            @RequestParam(required = false) String sub,
            @RequestParam(required = false) String domain) {
        // Fail-closed: a missing/blank field is a DENY (403), not a 400 — nginx
        // auth_request only distinguishes 2xx (allow) from non-2xx (deny), and a uniform
        // 403 keeps a malformed probe indistinguishable from a forged signature.
        if (isBlank(path) || isBlank(sig) || isBlank(exp) || isBlank(sub) || isBlank(domain)) {
            return DENY;
        }
        long expMillis;
        try {
            expMillis = Long.parseLong(exp);
        } catch (NumberFormatException e) {
            return DENY;   // unparseable expiry — reject
        }
        // Expiry + constant-time HMAC check live in the token service (the same code the
        // sign side uses), so verify stays byte-symmetric with sign.
        return tokenService.verify(sub, domain, path, sig, expMillis) ? ALLOW : DENY;
    }

    /** Null/blank guard for the verify query parameters (fail-closed). */
    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * The path-safety + owner two-wall + signing body, reached ONLY after the DEFAULT-DENY
     * use gate ({@link TubeAccessGuard#assertCanUse}) has completed.
     */
    private Mono<ResponseEntity<TubeMediaDto.SignedUrl>> signGranted(String path, Authentication auth) {

        // ── path safety (wall 2a) ─────────────────────────────────────────────
        if (!PATH_PATTERN.matcher(path).matches()) {
            return Mono.error(ApiException.badRequest(
                    "path is invalid — must match /<domain>/<subject>/... with no .. or //"));
        }

        // ── extract domain + subject from the path ────────────────────────────
        // Path has been validated to have the shape /seg1/seg2/rest
        String[] parts = path.split("/", 4);   // ["", domain, subject, rest]
        String pathDomain = parts[1];
        String pathSubject = parts[2];

        // ── resolve principal's domain + subject ──────────────────────────────
        // Domain is read from the already-stamped DOMAIN_<x> authority (emitted by
        // CasdoorAuthorities at JWT validation time) — the same authority the rest of the
        // BFF reads via Roles.domainOf(authorities).  Reading from the authority (rather
        // than re-deriving from the issuer via DomainRegistry) keeps this controller free
        // of the DomainRegistry dependency and is consistent with how TubeAccessGuard
        // reads isSuperadmin from authorities.  Fail-closed: Roles.domainOf returns null
        // on zero or >1 DOMAIN_ authorities (injection guard), which the check below rejects.
        if (!(auth.getPrincipal() instanceof Jwt jwt)) {
            // Non-JWT principal (should not reach here in production, but fail-closed).
            return Mono.error(ApiException.forbidden("JWT principal required for media signing"));
        }
        String jwtSubject = jwt.getSubject();
        String jwtDomain  = Roles.domainOf(auth.getAuthorities());

        // ── owner two-wall (wall 2b) ──────────────────────────────────────────
        // Domain check: the path must embed the calling user's own brand.
        if (jwtDomain == null || !jwtDomain.equals(pathDomain)) {
            return Mono.error(ApiException.forbidden(
                    "path domain does not match the caller's brand"));
        }
        // Subject check: the path must embed the calling user's own subject.
        if (jwtSubject == null || !jwtSubject.equals(pathSubject)) {
            return Mono.error(ApiException.forbidden(
                    "path subject does not match the caller's JWT subject"));
        }

        // ── sign ──────────────────────────────────────────────────────────────
        String qs = tokenService.sign(jwtSubject, jwtDomain, path);
        String url = "/tube/content" + path + "?" + qs;
        Instant expiresAt = Instant.now().plusMillis(TubeMediaTokenService.TTL_MILLIS);

        return Mono.just(ResponseEntity.ok(new TubeMediaDto.SignedUrl(url, expiresAt)));
    }
}
