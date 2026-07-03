package systems.snapdragon.tubebff.access;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.Roles;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.tubebff.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

/**
 * Load-bearing enforcement of the {@code tube_access} use grant / timeout / ban overlay.
 * Resolves whether a request principal may USE the tube service by reading the dynamic
 * desired-state table and applying the precedence rule.
 *
 * <h2>Stance (DEFAULT-DENY and GRANT-ONLY)</h2>
 *
 * <p>The base {@code ROLE_TUBE} is the gateway route/connect floor only; it does NOT by
 * itself confer use. An active {@link TubeAccess#TYPE_USE} grant is the only thing that
 * lifts a user above the default-deny floor (besides the SUPERADMIN infra exemption).
 *
 * <p>A static {@code @PreAuthorize} on the controller cannot consult the DB for a
 * per-principal grant or ban — this guard is invoked programmatically by every
 * use-affecting endpoint.
 *
 * <h2>Reactive pipeline (assertCanUse)</h2>
 *
 * <pre>
 *   auth
 *     │
 *     ├─ SUPERADMIN? ──yes──► Mono.empty() (exempt, no DB read)
 *     │
 *     └─ resolve (subject, domain)
 *          │
 *          ▼
 *     repo.activeFor(subject, domain)               ← Flux of ACTIVE rows
 *          │
 *          ▼
 *     .filter(isEffectiveAt(now))                   ← drop expired timeouts
 *          │
 *          ▼
 *     .collectList()
 *          │
 *          ▼
 *     banned?  ──yes──► Mono.error(403 "banned")
 *     granted? ──yes──► Mono.empty()  (allowed)
 *     default  ──────► Mono.error(403 "no grant")
 * </pre>
 *
 * <h2>Precedence rule</h2>
 *
 * <ul>
 *   <li>DEFAULT-DENY: no grant means cannot use;</li>
 *   <li>an ACTIVE non-expired BAN denies even a principal who holds an active USE grant
 *       (<b>ban &gt; grant</b>);</li>
 *   <li>SUPERADMIN is exempt from the ban (infra control plane) — checked first,
 *       before any DB read;</li>
 *   <li>an EXPIRED timeout auto-restores: {@link TubeAccess#isEffectiveAt} treats a
 *       past {@code expires_at} as inactive without a write.</li>
 * </ul>
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *   Caller           │ Outcome
 *   ─────────────────┼──────────────────────────────────────────────────────────
 *   ROLE_SUPERADMIN  │ always allowed (exempt) — no DB read
 *   ROLE_TUBE (grant)│ allowed when active use grant AND no active ban
 *   ROLE_TUBE (ban)  │ 403 — banned (even if a grant also exists)
 *   ROLE_TUBE (none) │ 403 — no use grant (default-deny)
 * </pre>
 *
 * @see TubeAccess
 * @see TubeAccessRepository
 * @see systems.snapdragon.tubebff.security.PrincipalDomain
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
     * precedence.
     *
     * <p>Completes empty ({@code Mono<Void>}) when use is allowed; signals a 403
     * {@link ApiException} when an active ban/timeout denies use OR when there is no active
     * use grant. Compose a use-affecting endpoint chain as
     * {@code guard.assertCanUse(auth).then(Mono.defer(() -> yourHandler))}.
     *
     * @param auth the request principal; {@code null} or non-JWT principal is treated as
     *             a non-superadmin with the default domain (no DB bypass)
     * @return an empty {@code Mono} completing when use is permitted, or an error
     *         {@code Mono} carrying a 403 {@link ApiException} when denied
     * @throws ApiException (403) embedded in the returned Mono when:
     *         (a) the principal has an active ban/timeout, or
     *         (b) the principal has no active use grant (default-deny)
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
