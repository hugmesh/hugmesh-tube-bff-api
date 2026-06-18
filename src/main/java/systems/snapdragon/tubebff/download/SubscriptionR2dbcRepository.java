package systems.snapdragon.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@code tube_subscription} — the download-queue ENQUEUE
 * SOURCE view (latest-video fields; schema in Liquibase
 * {@code db/changelog/006-tube-subscription.xml} + {@code 007-...-download-fields.xml}).
 * MATCHES the federation exemplar: derived finder pairs (domain-scoped vs SUPERADMIN
 * un-pinned) + one constant-{@code @Query} for the in-place latest-video refresh that the
 * find-then-write upsert performs (a partial UPDATE derivation cannot express).
 */
public interface SubscriptionR2dbcRepository extends R2dbcRepository<TubeSubscription, String> {

    String REFRESH_LATEST =
            "UPDATE tube_subscription SET channel_title = :ct, "
            + "latest_video_id = :lvi, latest_video_title = :lvt, updated_at = now() "
            + "WHERE id = :id";

    @Modifying
    @Query(REFRESH_LATEST)
    Mono<Long> refreshLatest(@Param("id") String id, @Param("ct") String ct,
                             @Param("lvi") String lvi, @Param("lvt") String lvt);

    // ── listForOwner: WHERE user_subject [AND domain] ORDER BY channel_title, channel_id
    Flux<TubeSubscription> findByUserSubjectOrderByChannelTitleAscChannelIdAsc(String userSubject);

    Flux<TubeSubscription> findByUserSubjectAndDomainOrderByChannelTitleAscChannelIdAsc(
            String userSubject, String domain);

    // ── findByChannel: WHERE user_subject AND channel_id [AND domain] -> first ──────
    Mono<TubeSubscription> findFirstByUserSubjectAndChannelId(String userSubject, String channelId);

    Mono<TubeSubscription> findFirstByUserSubjectAndChannelIdAndDomain(
            String userSubject, String channelId, String domain);
}
