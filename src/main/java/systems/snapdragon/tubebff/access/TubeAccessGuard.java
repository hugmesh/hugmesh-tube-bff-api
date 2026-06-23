package systems.snapdragon.tubebff.access;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;
import systems.snapdragon.commons.security.Roles;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;
import java.util.List;

/**
 * THE LOAD-BEARING enforcement of the use grant/timeout/ban overlay: it resolves
 * whether a request principal may USE the tube service by reading the DYNAMIC
 * {@code tube_access} desired-state and applying the precedence rule. The
 * {@code OwncastBroadcastGuard} twin — with the SAME deliberate stance: use is
 * <b>DEFAULT-DENY and GRANT-ONLY</b>. The base {@code ROLE_TUBE} is the gateway
 * route/connect floor only; it does <b>NOT</b> by itself confer use — an active
 * {@link TubeAccess#TYPE_USE} grant is the ONLY thing that lifts a user above the
 * default-deny floor (besides the SUPERADMIN infra exemption).
 *
 * <p>A static {@code @PreAuthorize} on the controller CANNOT consult the DB for a
 * per-principal grant or ban, so — exactly as owncast-bff / wiki-bff / admin-bff enforce
 * their overlays at request time rather than leaving them inert — this guard is invoked
 * programmatically by the use-affecting endpoints, loads the principal's
 * {@code tube_access} rows for their brand, and decides:
 *
 * <pre>
 *   USE ALLOWED  ==  SUPERADMIN (infra, exempt — no DB read)
 *                    OR ( an ACTIVE non-expired USE grant for this user+domain
 *                         AND NOT an ACTIVE non-expired BAN/TIMEOUT for this user+domain )
 * </pre>
 *
 * <p>PRECEDENCE — the load-bearing rule:
 * <ul>
 *   <li>DEFAULT-DENY: no grant ⇒ cannot use (the bare ROLE_TUBE floor never substitutes
 *       for the grant);</li>
 *   <li>an ACTIVE non-expired BAN/TIMEOUT DENIES even a principal who holds an active
 *       USE grant (<b>ban &gt; grant</b> — the ban wins);</li>
 *   <li>SUPERADMIN is UNAFFECTED by a ban (infra control plane) — checked FIRST, before
 *       any DB read;</li>
 *   <li>an EXPIRED timeout auto-restores: {@link TubeAccess#isEffectiveAt} treats a past
 *       {@code expires_at} as no-longer-active, so the row stops denying WITHOUT a write.</li>
 * </ul>
 */
@Component
public class TubeAccessGuard {

    private final TubeAccessRepository repo;
    private final PrincipalDomain principalDomain;

    public TubeAccessGuard(TubeAccessRepository repo, PrincipalDomain principalDomain) {
        this.repo = repo;
        this.principalDomain = principalDomain;
    }

    /**
     * Enforce use access for the request principal, applying the DEFAULT-DENY overlay
     * precedence. Completes (passes through the empty Mono) when use is allowed; errors
     * with a 403 {@link ApiException} when an active ban/timeout denies it OR when there is
     * no active use grant. Wrap a use-affecting endpoint as
     * {@code guard.assertCanUse(auth).then(...)}.
     */
    public Mono<Void> assertCanUse(Authentication auth) {
        // SUPERADMIN is the infra control plane — exempt from the overlay (never banned
        // out, and may use the service without a grant), resolved with NO DB read.
        if (isSuperadmin(auth)) {
            return Mono.empty();
        }
        String domain = scopeOf(auth);
        String subject = subject(auth);
        Instant now = Instant.now();

        // Load the principal's ACTIVE overrides for THEIR brand and apply the precedence.
        return repo.activeFor(subject, domain)
                // An expired timeout auto-restores — skip rows whose effective window has closed.
                .filter(a -> a.isEffectiveAt(now))
                // Collect all active rows so the ban-vs-grant precedence decision sees the full set.
                .collectList()
                // Apply DEFAULT-DENY + ban-wins-over-grant precedence to the active row set.
                .flatMap(TubeAccessGuard::applyAccessPrecedence);
    }

    /**
     * Apply the ban-wins-over-grant DEFAULT-DENY precedence rule to the caller's active
     * overlay rows. An active ban/timeout denies even a grantee; no grant means denied.
     */
    private static Mono<Void> applyAccessPrecedence(List<TubeAccess> rows) {
        boolean banned = rows.stream()
                .anyMatch(a -> TubeAccess.TYPE_BANNED.equals(a.accessType()));
        boolean granted = rows.stream()
                .anyMatch(a -> TubeAccess.TYPE_USE.equals(a.accessType()));
        // PRECEDENCE: an active ban/timeout denies even a grantee (ban > grant).
        if (banned) {
            return Mono.error(ApiException.forbidden(
                    "tube use is banned for this principal in this brand"));
        }
        // DEFAULT-DENY + GRANT-ONLY: allowed ONLY when an active use grant
        // exists — the bare ROLE_TUBE floor does not substitute for it.
        if (granted) {
            return Mono.empty();
        }
        return Mono.error(ApiException.forbidden(
                "tube use requires an active grant (default-deny)"));
    }

    /** SUPERADMIN read from either the JWT roles claim (runtime shape) or the converted
     *  authorities (test/authorities-only shape). */
    private boolean isSuperadmin(Authentication auth) {
        if (auth == null) return false;
        if (auth.getPrincipal() instanceof Jwt jwt && Roles.isSuperadmin(jwt)) {
            return true;
        }
        return Roles.isSuperadmin(auth.getAuthorities());
    }

    /** The caller's brand — derived SERVER-SIDE from the validated JWT issuer
     *  ({@link PrincipalDomain}); the {@code default} domain for a non-JWT principal
     *  (test/single-tenant). NEVER a request field. SUPERADMIN never reaches this (it is
     *  short-circuited above), so the {@code null} bypass is never used by the guard. */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String d = principalDomain.forScope(jwt);
            return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    /** The acting principal's Casdoor subject — the key the overlay targets. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) {
            return jwt.getSubject();
        }
        return auth == null || auth.getName() == null ? "" : auth.getName();
    }
}
