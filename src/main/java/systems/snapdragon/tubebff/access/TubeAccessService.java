package systems.snapdragon.tubebff.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;

/**
 * The desired-state write surface for the {@code tube_access} use grant/timeout/ban
 * overlay — the API the {@link TubeAccessController} endpoints call. CLONED in
 * semantics from the owncast-bff {@code OwncastBroadcastService}: it is DELIBERATELY the
 * only write surface for the overlay; it writes/CASes the table and NEVER touches
 * Casdoor or the gateway directly. The request-time enforcement ({@link TubeAccessGuard})
 * is the sole reader of the table on the use path, so a write here changes who may use
 * the tube service on the next request.
 *
 * <p>All writes are DOMAIN-scoped: the acting principal's brand is derived SERVER-SIDE
 * from the validated issuer ({@link PrincipalDomain}) and stamped on the row, so a scoped
 * ADMIN of brand X can only grant/ban/restore WITHIN brand X; a SUPERADMIN (null scope)
 * writes to the platform {@code default} domain (its acts are cross-domain at read time).
 *
 * <ul>
 *   <li>{@link #grant} — give a USER an ACTIVE permanent {@code use} override
 *       (expires_at NULL) — the way to lift a user above the default-deny use floor.</li>
 *   <li>{@link #timeout} — a {@code banned} override with a FUTURE expires_at: it DENIES
 *       use until the TTL, then auto-restores (the enforcement read treats an expired row
 *       as inactive — no write needed on expiry).</li>
 *   <li>{@link #ban} — an ACTIVE permanent {@code banned} override (expires_at NULL).</li>
 *   <li>{@link #revoke} — CAS the active override of a type to {@code revoked} (the row
 *       is retained = audit). Restoring use = revoke the {@code banned} row; revoking a
 *       grant = revoke the {@code use} row.</li>
 * </ul>
 * Each write is IDEMPOTENT on an existing active row of the same type (returned unchanged
 * — the partial-unique index is the race backstop).
 */
@Service
public class TubeAccessService {

    private static final Logger log = LoggerFactory.getLogger(TubeAccessService.class);

    private final TubeAccessRepository repo;
    private final PrincipalDomain principalDomain;

    public TubeAccessService(TubeAccessRepository repo, PrincipalDomain principalDomain) {
        this.repo = repo;
        this.principalDomain = principalDomain;
    }

    /** Grant {@code userSubject} a PERMANENT may-use override in the actor's brand. */
    public Mono<TubeAccess> grant(String userSubject, String reason, Authentication actor) {
        return upsertActive(userSubject, TubeAccess.TYPE_USE, null, reason, actor, "grant");
    }

    /**
     * TIMEOUT {@code userSubject}: a {@code banned} override with a FUTURE expiry — denies
     * use for {@code ttlSeconds}, then auto-restores (the enforcement read stops denying
     * once {@code expires_at <= now}, no write required).
     */
    public Mono<TubeAccess> timeout(String userSubject, long ttlSeconds, String reason,
                                    Authentication actor) {
        Instant expiresAt = Instant.now().plus(Duration.ofSeconds(ttlSeconds));
        return upsertActive(userSubject, TubeAccess.TYPE_BANNED, expiresAt, reason, actor, "timeout");
    }

    /** BAN {@code userSubject}: a PERMANENT {@code banned} override (expires_at NULL). */
    public Mono<TubeAccess> ban(String userSubject, String reason, Authentication actor) {
        return upsertActive(userSubject, TubeAccess.TYPE_BANNED, null, reason, actor, "ban");
    }

    /**
     * REVOKE the active override of {@code accessType} for {@code userSubject} in the
     * actor's brand (CAS active->revoked; the row is retained = audit). A no-op (empty)
     * when there is no active override of that type. Restoring use = revoke the
     * {@code banned} row; removing a grant = revoke the {@code use} row.
     */
    public Mono<Void> revoke(String userSubject, String accessType, Authentication actor) {
        String domain = scopeOf(actor);
        // A scoped admin can only resolve (and therefore revoke) a row in their own brand;
        // another brand's active override is invisible, so the revoke is a no-op for them.
        return repo.findActive(userSubject, accessType, domain)
                .flatMap(active -> repo.revoke(active.id())
                        .doOnNext(n -> log.info("[tube-access] revoked {} for {} by {} (id={}, rows={})",
                                accessType, userSubject, subject(actor), active.id(), n)))
                .then();
    }

    /** All active overrides VISIBLE to the actor (MANAGE read surface). Scoped admin sees
     *  only their brand; SUPERADMIN sees all. */
    public Flux<TubeAccess> listActive(Authentication actor) {
        return repo.listActive(scopeOf(actor));
    }

    /** The full history (active + revoked) for a principal VISIBLE to the actor — the
     *  audit read (revoked rows retained). */
    public Flux<TubeAccess> historyFor(String userSubject, Authentication actor) {
        return repo.historyFor(userSubject, scopeOf(actor));
    }

    // ── helpers ────────────────────────────────────────────────────────

    /** Idempotent insert-active: an existing active row of the same type VISIBLE to the
     *  actor's scope is returned unchanged (a re-grant/re-ban while active is a no-op);
     *  otherwise a new active row is stamped with the actor's brand. */
    private Mono<TubeAccess> upsertActive(String userSubject, String accessType, Instant expiresAt,
                                          String reason, Authentication actor, String verb) {
        String domain = scopeOf(actor);
        String by = subject(actor);
        return repo.findActive(userSubject, accessType, domain)
                .doOnNext(existing -> log.info("[tube-access] {} {} already active for {} (id={}) — no-op",
                        verb, accessType, userSubject, existing.id()))
                .switchIfEmpty(Mono.defer(() ->
                        repo.insertActive(userSubject, accessType, expiresAt, reason, by, domain)
                                .doOnNext(a -> log.info("[tube-access] {} created {} for {} "
                                                + "(id={}, expiresAt={}, domain={})",
                                        verb, accessType, userSubject, a.id(), expiresAt, a.domain()))));
    }

    /** The actor's brand — {@code null} for SUPERADMIN (cross-domain), else the
     *  issuer-derived {@code DOMAIN_<x>}; {@code default} for a non-JWT (test) principal.
     *  NEVER a request field. */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return principalDomain.forScope(jwt);
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    /** The acting principal's Casdoor subject (the granted_by key). */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) {
            return jwt.getSubject();
        }
        return auth == null || auth.getName() == null ? "@system" : auth.getName();
    }
}
