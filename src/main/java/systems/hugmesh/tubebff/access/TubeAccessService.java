package systems.hugmesh.tubebff.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.tubebff.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;

/**
 * The desired-state write surface for the {@code tube_access} use grant / timeout / ban
 * overlay — the API {@link TubeAccessController} endpoints delegate to.
 *
 * <p>This service is the ONLY write surface for the overlay; it writes/CASes the table
 * and never touches Casdoor or the gateway directly. The request-time enforcement
 * ({@link TubeAccessGuard}) is the sole reader on the use path, so a write here changes
 * who may use the tube service on the very next request.
 *
 * <h2>Operations</h2>
 *
 * <ul>
 *   <li>{@link #grant} — ACTIVE permanent {@code use} override ({@code expires_at = NULL})
 *       that lifts a user above the default-deny floor.</li>
 *   <li>{@link #timeout} — {@code banned} override with a FUTURE {@code expires_at}: denies
 *       use until the TTL then auto-restores; no write needed on expiry.</li>
 *   <li>{@link #ban} — ACTIVE permanent {@code banned} override
 *       ({@code expires_at = NULL}).</li>
 *   <li>{@link #revoke} — CAS {@code active -> revoked} for one override type (retained as
 *       audit). Restoring use = revoke {@code banned}; removing a grant = revoke
 *       {@code use}.</li>
 * </ul>
 *
 * <p>Each write is IDEMPOTENT on an existing active row of the same type (returned
 * unchanged — the partial-unique index is the race backstop).
 *
 * <h2>Domain scoping</h2>
 *
 * <p>All writes are domain-scoped: the acting principal's brand is derived SERVER-SIDE
 * from the validated issuer via {@link PrincipalDomain} and stamped on the row. A scoped
 * ADMIN of brand X can only grant/ban/restore WITHIN brand X. A SUPERADMIN (null scope)
 * is pinned to the platform {@code default} domain for writes (cross-domain at read time
 * via the un-pinned repo finders).
 *
 * @see TubeAccessController
 * @see TubeAccessGuard
 * @see TubeAccessRepository
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

    /**
     * Grant {@code userSubject} a PERMANENT may-use override ({@code type=use,
     * expires_at=null}) in the acting admin's brand. Idempotent: re-grant while active is
     * a no-op that returns the existing row.
     *
     * @param userSubject the Casdoor subject of the user to grant
     * @param reason      optional free-text audit reason
     * @param actor       the acting admin's authentication (subject + domain server-derived)
     * @return a {@code Mono} emitting the created or existing {@link TubeAccess} row
     */
    public Mono<TubeAccess> grant(String userSubject, String reason, Authentication actor) {
        return upsertActive(userSubject, TubeAccess.TYPE_USE, null, reason, actor, "grant");
    }

    /**
     * Timeout {@code userSubject}: a {@code banned} override with a FUTURE expiry. Denies
     * use for {@code ttlSeconds}, then auto-restores — the enforcement read stops denying
     * once {@code expires_at <= now} without any write.
     *
     * @param userSubject the Casdoor subject of the user to timeout
     * @param ttlSeconds  the ban duration in seconds (must be positive)
     * @param reason      optional free-text audit reason
     * @param actor       the acting admin's authentication
     * @return a {@code Mono} emitting the created {@link TubeAccess} row
     */
    public Mono<TubeAccess> timeout(String userSubject, long ttlSeconds, String reason,
                                    Authentication actor) {
        Instant expiresAt = Instant.now().plus(Duration.ofSeconds(ttlSeconds));
        return upsertActive(userSubject, TubeAccess.TYPE_BANNED, expiresAt, reason, actor, "timeout");
    }

    /**
     * Permanently ban {@code userSubject}: a {@code banned} override with
     * {@code expires_at = null}. An active ban takes precedence over an active use grant
     * (ban &gt; grant).
     *
     * @param userSubject the Casdoor subject of the user to ban
     * @param reason      optional free-text audit reason
     * @param actor       the acting admin's authentication
     * @return a {@code Mono} emitting the created or existing {@link TubeAccess} row
     */
    public Mono<TubeAccess> ban(String userSubject, String reason, Authentication actor) {
        return upsertActive(userSubject, TubeAccess.TYPE_BANNED, null, reason, actor, "ban");
    }

    /**
     * Revoke the active override of {@code accessType} for {@code userSubject} in the
     * acting admin's brand (CAS {@code active -> revoked}; the row is retained as audit).
     * A no-op (empty Mono) when there is no active override of that type. Restoring use =
     * revoke the {@code banned} row; removing a grant = revoke the {@code use} row.
     *
     * @param userSubject the Casdoor subject of the user whose override to revoke
     * @param accessType  {@link TubeAccess#TYPE_USE} or {@link TubeAccess#TYPE_BANNED}
     * @param actor       the acting admin's authentication (domain server-derived)
     * @return an empty {@code Mono} that completes when the revoke (or no-op) finishes
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

    /**
     * All active overrides visible to the actor — the MANAGE read surface. A scoped admin
     * sees only their brand; SUPERADMIN sees all brands.
     *
     * @param actor the acting SUPERADMIN's authentication
     * @return a {@code Flux} of all active {@link TubeAccess} rows visible to this caller
     */
    public Flux<TubeAccess> listActive(Authentication actor) {
        return repo.listActive(scopeOf(actor));
    }

    /**
     * The full history (active + revoked) for a principal visible to the actor — the
     * audit read. Revoked rows are never deleted; this stream is the complete lifecycle log.
     *
     * @param userSubject the Casdoor subject whose history to retrieve
     * @param actor       the acting SUPERADMIN's authentication
     * @return a {@code Flux} of all {@link TubeAccess} rows for the subject, newest first
     */
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
