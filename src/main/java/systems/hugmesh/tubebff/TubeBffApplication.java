package systems.hugmesh.tubebff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Tube BFF — the access GOVERNANCE and media-access plane of the LocalTube video
 * optional service (x86 + GPU-dependent, ships DEFAULT-OFF). Serves the gateway path
 * {@code /bff/tube/**} as a reactive Spring WebFlux resource server; validated
 * Casdoor JWTs are the authentication layer.
 *
 * <h2>Architecture</h2>
 *
 * <p>This BFF owns:
 * <ul>
 *   <li><b>PR2</b> — {@code tube_access} desired-state overlay: per-principal may-use
 *       grant/timeout/ban records that gate whether a domain-controlled user may use the
 *       tube service above the {@code ROLE_TUBE} base role.</li>
 *   <li><b>PR3</b> — Google (youtube.readonly) OAuth connect / subscriptions sync:
 *       the dedicated Web client OAuth flow + AES-256-GCM refresh-token at-rest encryption
 *       + idempotent channel upsert.</li>
 *   <li><b>PR4</b> — yt-dlp download work queue: the {@code tube_download_job} table,
 *       the user enqueue surface, and the internal worker claim/report endpoints.</li>
 *   <li><b>PR5</b> — short-TTL HMAC-signed media URLs for the tube-media Nginx sidecar
 *       that serves the per-domain content PVC.</li>
 * </ul>
 *
 * <p>This BFF is NOT the media plane — downloaded content lives on a per-domain content
 * PVC served range/HLS through a SEPARATE be-gateway route:
 *
 * <pre>
 *   browser → fe-gateway /bff/tube/**       → THIS BFF → tube_access / subscriptions / jobs
 *   browser → be-gateway /tube/content/**   → tube-media Nginx sidecar (PVC, PR5)
 * </pre>
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *   Caller              │ Path prefix                   │ What they may do
 *   ────────────────────┼───────────────────────────────┼──────────────────────────────────────
 *   ROLE_TUBE (user)    │ /bff/tube/**                  │ use-gate enforced first (active grant
 *                       │                               │ AND no active ban); own subscriptions,
 *                       │                               │ own download queue, media sign
 *   ROLE_TUBE (no grant)│ /bff/tube/**                  │ 403 from TubeAccessGuard (default-deny)
 *   ROLE_ADMIN          │ /bff/tube/admin/**            │ TUBE_GOVERN: grant/timeout/ban/restore +
 *                       │                               │ set storage budget (own brand only)
 *   ROLE_SUPERADMIN     │ /bff/tube/superadmin/**       │ TUBE_MANAGE: list-all + history;
 *                       │                               │ also reaches all admin gates via hierarchy
 *   ROLE_TUBE_WORKER    │ /bff/tube/internal/**         │ claim/report download jobs (machine only;
 *                       │                               │ deliberately OUTSIDE the human hierarchy)
 *   (unauthenticated)   │ /actuator/health, /info       │ k8s probes, no token required
 * </pre>
 *
 * <h2>Security axioms</h2>
 *
 * <ul>
 *   <li><b>DEFAULT-DENY use</b>: bare {@code ROLE_TUBE} is the route/connect floor only —
 *       it does NOT confer use. An active {@code tube_access} use grant (or the SUPERADMIN
 *       infra exemption) is required. Enforced programmatically by
 *       {@link systems.hugmesh.tubebff.access.TubeAccessGuard} (a static SpEL
 *       cannot consult the DB for a per-principal grant or ban).</li>
 *   <li><b>Domain-scoped</b>: every table has a {@code domain} column stamped server-side
 *       from the validated JWT issuer. A scoped ADMIN of brand X governs only brand X.
 *       SUPERADMIN is the cross-domain bypass (and is exempt from a ban).</li>
 *   <li><b>Audit trail</b>: {@code tube_access} rows are never hard-deleted — revoked rows
 *       are retained as the audit log.</li>
 *   <li><b>Secrets at rest</b>: the Google refresh token is stored ONLY as AES-256-GCM
 *       ciphertext ({@link systems.hugmesh.tubebff.google.TokenCipher}).</li>
 * </ul>
 *
 * @see systems.hugmesh.tubebff.access.TubeAccessGuard
 * @see systems.hugmesh.tubebff.access.TubeAccessController
 * @see systems.hugmesh.tubebff.google.GoogleConnectController
 * @see systems.hugmesh.tubebff.download.TubeDownloadController
 * @see systems.hugmesh.tubebff.media.TubeMediaController
 * @see systems.hugmesh.tubebff.config.SecurityConfig
 */
@SpringBootApplication
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
public class TubeBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(TubeBffApplication.class, args);
    }
}
