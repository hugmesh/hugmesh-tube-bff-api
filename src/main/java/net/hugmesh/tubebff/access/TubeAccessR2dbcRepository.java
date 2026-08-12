package net.hugmesh.tubebff.access;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for the {@code tube_access} table.
 *
 * <p>Schema: Liquibase {@code db/changelog/004-tube-access.xml}. Follows the
 * hugmesh-federation-api reactive-repository exemplar: derived finders where derivation
 * suffices, plus one constant-{@code @Query} ({@link #REVOKE_CAS}) for the guarded CAS
 * update that derivation cannot express.
 *
 * <h2>Domain-scope pairs</h2>
 *
 * <p>Every read has two variants to implement the
 * {@link net.hugmesh.commons.tenancy.DomainScope} null-vs-non-null predicate:
 * a brand-scoped variant ({@code ...AndDomain...}) for a scoped admin and an un-pinned
 * variant for the SUPERADMIN ({@code null} domain = no predicate).
 * {@link TubeAccessRepository} dispatches between the pair on
 * {@code DomainScope.isUnscoped(domain)}.
 *
 * <h2>State parameter convention</h2>
 *
 * <p>The {@code state = 'active'} filter is passed as the {@link TubeAccess#STATE_ACTIVE}
 * constant argument through the derived {@code AndState} clause, preserving the literal
 * exactly.
 *
 * @see TubeAccessRepository
 * @see TubeAccess
 */
public interface TubeAccessR2dbcRepository extends R2dbcRepository<TubeAccess, String> {

    /**
     * The CAS SQL string: transitions one row from {@code active} to {@code revoked},
     * stamping {@code revoked_at = now()}, guarded on {@code state = 'active'} so exactly
     * one concurrent writer wins. Derivation cannot express a {@code now()} call or a
     * literal-state SET, so this is a constant {@code @Query} per the data-access standard.
     */
    String REVOKE_CAS =
            "UPDATE tube_access SET state = 'revoked', revoked_at = now() "
            + "WHERE id = :id AND state = 'active'";

    /**
     * CAS {@code active -> revoked} for one row by id. Returns the number of rows updated:
     * 1 when this caller won the race; 0 when the row was already revoked by a concurrent
     * writer.
     *
     * @param id the row id to revoke
     * @return a {@code Mono} emitting the rows-updated count (0 or 1)
     */
    @Modifying
    @Query(REVOKE_CAS)
    Mono<Long> revokeIfActive(@Param("id") String id);

    // ── DB-generated UUID PK insert (changelog 008): id is OMITTED so Postgres fills it
    //    from the (gen_random_uuid())::text column DEFAULT; RETURNING id reads the generated
    //    string back. A plain (non-@Modifying) @Query returning the new id — derivation
    //    cannot express an INSERT ... RETURNING. The 9 supplied columns are exactly the
    //    non-id values the former save(new TubeAccess(id, ...)) persisted (created_at is the
    //    app-stamped Instant, as before), so the row is BYTE-IDENTICAL except the id source.
    String INSERT_ACTIVE_RETURNING_ID = """
            INSERT INTO tube_access \
            (domain, user_subject, access_type, state, granted_by_subject, reason, \
             created_at, expires_at, revoked_at) \
            VALUES (:domain, :userSubject, :accessType, :state, :grantedBy, :reason, \
             :createdAt, :expiresAt, :revokedAt) \
            RETURNING id""";

    @Query(INSERT_ACTIVE_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("userSubject") String userSubject,
                                   @Param("accessType") String accessType,
                                   @Param("state") String state,
                                   @Param("grantedBy") String grantedBy,
                                   @Param("reason") String reason,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("expiresAt") Instant expiresAt,
                                   @Param("revokedAt") Instant revokedAt);

    // ── findActive: WHERE user_subject AND access_type AND state ['active'] [AND domain]
    //               ORDER BY created_at DESC, id  -> first ──────────────────────────
    Mono<TubeAccess> findFirstByUserSubjectAndAccessTypeAndStateOrderByCreatedAtDescIdAsc(
            String userSubject, String accessType, String state);

    Mono<TubeAccess> findFirstByUserSubjectAndAccessTypeAndStateAndDomainOrderByCreatedAtDescIdAsc(
            String userSubject, String accessType, String state, String domain);

    // ── activeFor: WHERE user_subject AND state ['active'] [AND domain]
    //              ORDER BY access_type, created_at DESC ───────────────────────────
    Flux<TubeAccess> findByUserSubjectAndStateOrderByAccessTypeAscCreatedAtDesc(
            String userSubject, String state);

    Flux<TubeAccess> findByUserSubjectAndStateAndDomainOrderByAccessTypeAscCreatedAtDesc(
            String userSubject, String state, String domain);

    // ── listActive: WHERE state ['active'] [AND domain]
    //              ORDER BY domain, user_subject, access_type ───────────────────────
    Flux<TubeAccess> findByStateOrderByDomainAscUserSubjectAscAccessTypeAsc(String state);

    Flux<TubeAccess> findByStateAndDomainOrderByDomainAscUserSubjectAscAccessTypeAsc(
            String state, String domain);

    // ── historyFor: WHERE user_subject [AND domain] ORDER BY created_at DESC, id ────
    Flux<TubeAccess> findByUserSubjectOrderByCreatedAtDescIdAsc(String userSubject);

    Flux<TubeAccess> findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(
            String userSubject, String domain);
}
