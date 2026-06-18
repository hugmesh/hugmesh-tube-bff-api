package systems.snapdragon.tubebff.google;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@code tube_google_link} — the per-(brand,user) Google
 * OAuth connection (schema in Liquibase {@code db/changelog/005-tube-google-link.xml}).
 * Owner-scoped, fail-closed, single-domain (no SUPERADMIN bypass). MATCHES the federation
 * exemplar: a derived live-connection finder + constant-{@code @Query} soft-revoke /
 * reauth-flag UPDATEs (literal-state / now() SETs derivation cannot express).
 *
 * <p>The connection is NEVER hard-deleted — a disconnect soft-revokes (stamps
 * {@code revoked_at}); the LIVE connection is the one with {@code revoked_at IS NULL}.
 */
public interface TubeGoogleLinkR2dbcRepository extends R2dbcRepository<TubeGoogleLink, String> {

    String SOFT_REVOKE =
            "UPDATE tube_google_link SET revoked_at = now() "
            + "WHERE domain = :domain AND user_subject = :user AND revoked_at IS NULL";

    @Modifying
    @Query(SOFT_REVOKE)
    Mono<Long> softRevoke(@Param("domain") String domain, @Param("user") String user);

    String MARK_REAUTH =
            "UPDATE tube_google_link SET reauth_required = true "
            + "WHERE domain = :domain AND user_subject = :user AND revoked_at IS NULL";

    @Modifying
    @Query(MARK_REAUTH)
    Mono<Long> markReauthRequired(@Param("domain") String domain, @Param("user") String user);

    /** The LIVE connection for an owner in their brand ({@code revoked_at IS NULL}), newest
     *  first. Owner+domain scoped (fail-closed; no cross-brand match). */
    Mono<TubeGoogleLink> findFirstByDomainAndUserSubjectAndRevokedAtIsNullOrderByConnectedAtDescIdAsc(
            String domain, String userSubject);
}
