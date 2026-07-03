package systems.snapdragon.tubebff.access;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for the {@code tube_access} desired-state overlay — the use
 * grant / timeout / ban table.
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link TubeAccessR2dbcRepository}, the
 * Spring Data R2DBC interface (DERIVED finders + one constant-{@code @Query} CAS),
 * matching the snapdragon-federation-api reactive-repository exemplar. The public
 * method surface, ordering, filters, and never-delete / CAS-active->revoked audit
 * semantics are UNCHANGED. The id generation strategy is NOT unchanged: changelog 008
 * subsequently moved ids from app-generated UUIDs to a DB-generated column default
 * ({@code (gen_random_uuid())::text DEFAULT}) surfaced via {@code RETURNING id} — see
 * {@link #insertActive}.
 *
 * <h2>Domain-scope dispatch</h2>
 *
 * <p>Reads are DOMAIN-scoped via {@link DomainScope}: a scoped admin only ever resolves
 * rows in their own brand; a {@code null} or blank domain is the SUPERADMIN cross-domain
 * bypass (no predicate). This class dispatches onto the un-pinned vs
 * {@code ...AndDomain...} derived finder pair based on
 * {@code DomainScope.isUnscoped(domain)}.
 *
 * @see TubeAccessR2dbcRepository
 * @see TubeAccess
 * @see TubeAccessService
 */
@Repository
public class TubeAccessRepository {

    private final TubeAccessR2dbcRepository repo;

    public TubeAccessRepository(TubeAccessR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── writes (insert active; CAS active->revoked) ────────────────────

    /**
     * Insert a new ACTIVE override (DB-generated id, changelog 008) in the given brand
     * and return it. {@code expiresAt} null = PERMANENT; a future instant = a TIMEOUT.
     * The {@code domain}
     * is the acting principal's brand (defaulted to the platform {@code default} domain
     * for a SUPERADMIN unscoped write so a stamped row always carries a concrete brand).
     */
    public Mono<TubeAccess> insertActive(String userSubject, String accessType, Instant expiresAt,
                                         String reason, String grantedBy, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        Instant createdAt = Instant.now();
        // The id is DB-generated ((gen_random_uuid())::text DEFAULT, changelog 008): the
        // INSERT omits it and RETURNING id hands back the generated id, which we render into
        // the returned row (every other field unchanged from the former app-minted insert).
        return repo.insertReturningId(dom, userSubject, accessType, TubeAccess.STATE_ACTIVE,
                        grantedBy, reason, createdAt, expiresAt, null)
                .map(id -> new TubeAccess(id, dom, userSubject, accessType,
                        TubeAccess.STATE_ACTIVE, grantedBy, reason, createdAt, expiresAt, null));
    }

    /**
     * CAS {@code active -> revoked} for one row by id, stamping {@code revoked_at = now()}.
     * Exactly one concurrent writer wins (rows-updated = 1); the others see 0. The row is
     * never hard-deleted.
     *
     * @param id the {@code tube_access} row id to revoke
     * @return a {@code Mono} emitting the rows-updated count (1 = won; 0 = already revoked)
     */
    public Mono<Long> revoke(String id) {
        return repo.revokeIfActive(id);
    }

    // ── reads (domain-scoped) ──────────────────────────────────────────

    /**
     * The most-recent active override of a specific type for a user, visible to the given
     * tenant scope. Brand-scoped for a scoped admin; un-pinned (no domain predicate) for the
     * SUPERADMIN ({@code null}/blank domain) bypass.
     *
     * @param userSubject the Casdoor subject of the target user
     * @param accessType  {@link TubeAccess#TYPE_USE} or {@link TubeAccess#TYPE_BANNED}
     * @param domain      the brand to scope to; {@code null}/blank = SUPERADMIN bypass
     * @return a {@code Mono} emitting the row, or empty if none is active
     */
    public Mono<TubeAccess> findActive(String userSubject, String accessType, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, TubeAccess.STATE_ACTIVE)
                : repo.findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, TubeAccess.STATE_ACTIVE, domain);
    }

    /**
     * Every ACTIVE override for a principal within a brand — the enforcement working set
     * consumed by {@link TubeAccessGuard#assertCanUse}.
     *
     * @param userSubject the Casdoor subject of the principal being checked
     * @param domain      the brand; {@code null}/blank = SUPERADMIN bypass (all brands)
     * @return a {@code Flux} of active {@link TubeAccess} rows for this principal + brand
     */
    public Flux<TubeAccess> activeFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, TubeAccess.STATE_ACTIVE)
                : repo.findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, TubeAccess.STATE_ACTIVE, domain);
    }

    /**
     * All ACTIVE overrides visible to the given tenant scope — the MANAGE read surface
     * exposed by {@code GET /superadmin/access}.
     *
     * @param domain the brand to scope to; {@code null}/blank = SUPERADMIN (all brands)
     * @return a {@code Flux} of active rows ordered by domain, user_subject, access_type
     */
    public Flux<TubeAccess> listActive(String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByStateOrderByDomainAscUserSubjectAscAccessTypeAsc(TubeAccess.STATE_ACTIVE)
                : repo.findByStateAndDomainOrderByDomainAscUserSubjectAscAccessTypeAsc(
                        TubeAccess.STATE_ACTIVE, domain);
    }

    /**
     * The full history (active + revoked) for a principal within a brand — the audit read
     * exposed by {@code GET /superadmin/access/{subject}/history}. Revoked rows are never
     * deleted, so this stream is the complete grant/ban audit log.
     *
     * @param userSubject the Casdoor subject whose history to retrieve
     * @param domain      the brand to scope to; {@code null}/blank = SUPERADMIN (all brands)
     * @return a {@code Flux} ordered by created_at DESC, id ASC
     */
    public Flux<TubeAccess> historyFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByCreatedAtDescIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(userSubject, domain);
    }
}
