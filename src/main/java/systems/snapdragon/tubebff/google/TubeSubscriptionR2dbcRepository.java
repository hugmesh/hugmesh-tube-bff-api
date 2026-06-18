package systems.snapdragon.tubebff.google;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@code tube_subscription} — a connected user's mirrored
 * YouTube channels (the Google-sync view: thumbnail + synced_at; schema in Liquibase
 * {@code db/changelog/006-tube-subscription.xml}). Owner-scoped, single-domain (no
 * SUPERADMIN bypass). MATCHES the federation exemplar: a derived owner+domain finder + one
 * constant-{@code @Query} for the in-place sync UPDATE (a partial update derivation cannot
 * express).
 */
public interface TubeSubscriptionR2dbcRepository extends R2dbcRepository<TubeSubscription, String> {

    String SYNC_UPDATE =
            "UPDATE tube_subscription SET channel_title = :title, "
            + "thumbnail_url = :thumb, synced_at = now() "
            + "WHERE domain = :domain AND user_subject = :user AND channel_id = :chan";

    @Modifying
    @Query(SYNC_UPDATE)
    Mono<Long> syncUpdate(@Param("domain") String domain, @Param("user") String user,
                          @Param("chan") String chan, @Param("title") String title,
                          @Param("thumb") String thumb);

    /** A user's subscribed channels in their brand, ORDER BY channel_title, channel_id.
     *  Owner + domain scoped (always pinned). */
    Flux<TubeSubscription> findByDomainAndUserSubjectOrderByChannelTitleAscChannelIdAsc(
            String domain, String userSubject);
}
