package systems.snapdragon.tubebff.access;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@code tube_access} (schema in Liquibase
 * {@code db/changelog/004-tube-access.xml}). MATCHES the snapdragon-federation-api
 * reactive-repository exemplar: a {@link R2dbcRepository} interface with DERIVED query
 * methods, plus a single {@code @Query} (a {@code static final String} constant, never
 * an inline literal) for the CAS update derivation cannot express.
 *
 * <p>The {@link systems.snapdragon.commons.tenancy.DomainScope} null-vs-non-null
 * predicate (a {@code null} domain = the SUPERADMIN cross-domain bypass = NO predicate)
 * is reproduced with PAIRS of derived finders — a brand-scoped variant
 * ({@code ...AndDomain...}) and an un-pinned variant — exactly as the federation
 * {@code FederationOverrideRepository} does ({@code findAllByOrderByTsDesc} vs
 * {@code findByDomainOrderByTsDesc}). {@link TubeAccessRepository} dispatches between
 * the pair on {@code DomainScope.isUnscoped(domain)}.
 *
 * <p>The {@code state = 'active'} filter is passed as the {@link TubeAccess#STATE_ACTIVE}
 * argument (a derived {@code AndState} param), preserving the original literal exactly.
 */
public interface TubeAccessR2dbcRepository extends R2dbcRepository<TubeAccess, String> {

    /** Compare-and-swap {@code active -> revoked} for one row id, stamping
     *  {@code revoked_at}, guarded on the current state so exactly ONE writer wins.
     *  Derivation cannot express the {@code now()} / literal-state SET, so this is a
     *  constant {@code @Query} (per the data-access standard). */
    String REVOKE_CAS =
            "UPDATE tube_access SET state = 'revoked', revoked_at = now() "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_CAS)
    Mono<Long> revokeIfActive(@Param("id") String id);

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
