package systems.snapdragon.tubebff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Tube BFF — the access GOVERNANCE plane of the LocalTube video optional service
 * (x86 + GPU-dependent, ships DEFAULT-OFF). It owns the {@code tube_access}
 * desired-state overlay (PR2) — the per-principal may-use grant/timeout/ban records
 * that gate whether a (domain-controlled) user may actually USE the tube service on
 * top of the {@code ROLE_TUBE} base role — and (PR3–PR5) the Google-connect /
 * subscriptions-sync, the yt-dlp downloader work queue, and the owner-private media
 * serving.
 *
 * <p>This BFF is NOT the media plane — the downloaded content lives on a per-domain
 * content PVC served range/HLS through a SEPARATE be-gateway route:
 *
 * <pre>browser -> fe-gateway /bff/tube/** -> THIS BFF -> tube_access Postgres overlay
 * browser -> be-gateway /tube/media/** (range/HLS) -> tube-media sidecar (per-domain content PVC, PR5)</pre>
 *
 * <p>This BFF wraps the governance store per ROLE + ACTION (defence in depth on top of
 * the gateway route-access ROLE_TUBE floor):
 *
 * <ul>
 *   <li>USE — DEFAULT-DENY, GRANT-ONLY: a principal may use the service iff an active
 *       non-expired {@code tube_access} use grant exists AND no active ban; the base
 *       {@code ROLE_TUBE} is the route/connect floor but does NOT by itself confer use.
 *       Enforced programmatically by {@code TubeAccessGuard} (a static SpEL cannot
 *       consult the DB).</li>
 *   <li>GOVERN (grant/timeout/ban/restore) — {@code TUBE_GOVERN = hasRole('ADMIN') or
 *       hasRole('SUPERADMIN')} — an ADMIN decides which of their domain's users may
 *       use the tube service;</li>
 *   <li>MANAGE — {@code TUBE_MANAGE = hasRole('SUPERADMIN')} — list-all + history
 *       (the service enable per-domain + GPU-node check + the wider quota/retention/
 *       cadence admin surface arrive in PR4/PR7/PR8).</li>
 * </ul>
 *
 * <p>Every surface is DOMAIN-SCOPED (multi-brand): the {@code domain} is derived
 * SERVER-SIDE from the validated token issuer, so a scoped ADMIN of brand X governs
 * ONLY brand X's users; SUPERADMIN is the cross-domain bypass (and is exempt from a
 * ban). The granting admin is tracked from the JWT subject ({@code granted_by_subject});
 * a caller can never act under another admin. The Google-connect / subscriptions /
 * download / owner-private viewing tables + workers + the {@code snapdragon-tube-ui}
 * remote arrive in later PRs (PR3–PR6) — this PR is the BFF skeleton + the use access
 * overlay + the default-deny guard only.
 */
@SpringBootApplication
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
public class TubeBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(TubeBffApplication.class, args);
    }
}
