package systems.snapdragon.tubebff.access;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code tube_access} — the use grant/timeout/ban OVERLAY's
 * desired-state table (schema in Liquibase {@code db/changelog/004-tube-access.xml}).
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link TubeAccessR2dbcRepository}, the
 * Spring Data R2DBC interface (DERIVED finders + one constant-{@code @Query} CAS),
 * matching the snapdragon-federation-api reactive-repository exemplar. The public
 * method surface, ordering, filters, app-generated UUID ids, and never-delete /
 * CAS-active->revoked audit semantics are UNCHANGED.
 *
 * <p>The READS are DOMAIN-scoped via {@link DomainScope}: a scoped admin only ever
 * resolves rows in THEIR brand; a {@code null}/blank domain is the SUPERADMIN
 * cross-domain bypass (no predicate) — dispatched here onto the un-pinned vs
 * {@code ...AndDomain...} derived finder pair.
 */
@Repository
public class TubeAccessRepository {

    private final TubeAccessR2dbcRepository repo;

    public TubeAccessRepository(TubeAccessR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── writes (insert active; CAS active->revoked) ────────────────────

    /**
     * Insert a new ACTIVE override (app-generated id) in the given brand and return it.
     * {@code expiresAt} null = PERMANENT; a future instant = a TIMEOUT. The {@code domain}
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
     * Compare-and-swap {@code active -> revoked} for one row id, stamping
     * {@code revoked_at}, guarded on the current state so only ONE writer wins (returns
     * the rows-updated count: 1 = this caller won, 0 = already revoked). The row is never
     * deleted.
     */
    public Mono<Long> revoke(String id) {
        return repo.revokeIfActive(id);
    }

    // ── reads (domain-scoped) ──────────────────────────────────────────

    /** The active override of a given type for a (user) VISIBLE to the given tenant
     *  scope. Brand-scoped, or un-pinned for the SUPERADMIN ({@code null} domain) bypass. */
    public Mono<TubeAccess> findActive(String userSubject, String accessType, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, TubeAccess.STATE_ACTIVE)
                : repo.findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
                        userSubject, accessType, TubeAccess.STATE_ACTIVE, domain);
    }

    /** Every ACTIVE override for a principal WITHIN a brand — the enforcement working set. */
    public Flux<TubeAccess> activeFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, TubeAccess.STATE_ACTIVE)
                : repo.findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
                        userSubject, TubeAccess.STATE_ACTIVE, domain);
    }

    /** All ACTIVE overrides VISIBLE to the given tenant scope — the MANAGE read surface. */
    public Flux<TubeAccess> listActive(String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByStateOrderByDomainAscUserSubjectAscAccessTypeAsc(TubeAccess.STATE_ACTIVE)
                : repo.findByStateAndDomainOrderByDomainAscUserSubjectAscAccessTypeAsc(
                        TubeAccess.STATE_ACTIVE, domain);
    }

    /** The full history (active + revoked) for a principal WITHIN a brand — the audit read. */
    public Flux<TubeAccess> historyFor(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByCreatedAtDescIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(userSubject, domain);
    }
}
