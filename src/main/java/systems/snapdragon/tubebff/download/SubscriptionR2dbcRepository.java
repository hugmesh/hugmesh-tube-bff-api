package systems.snapdragon.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for the {@code tube_subscription} table, serving the
 * download-queue enqueue source view (latest-video fields).
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml} +
 * {@code 007-...-download-fields.xml}. Follows the federation exemplar: derived finder
 * pairs (domain-scoped vs SUPERADMIN un-pinned) plus one constant-{@code @Query} for the
 * in-place latest-video refresh that a partial UPDATE derivation cannot express.
 *
 * @see SubscriptionRepository
 * @see systems.snapdragon.tubebff.download.TubeSubscription
 */
public interface SubscriptionR2dbcRepository extends R2dbcRepository<TubeSubscription, String> {

    String REFRESH_LATEST =
            "UPDATE tube_subscription SET channel_title = :ct, "
            + "latest_video_id = :lvi, latest_video_title = :lvt, updated_at = now() "
            + "WHERE id = :id";

    /**
     * In-place refresh of the latest-video fields for an existing subscription row.
     * Called by the find-then-write upsert in {@link SubscriptionRepository} when a
     * re-sync finds the (user, channel) row already present.
     *
     * @param id  the subscription row id to update
     * @param ct  the updated channel title
     * @param lvi the latest video id (the dedup key fed to the download queue)
     * @param lvt the latest video title (display label)
     * @return a {@code Mono} emitting rows-updated (1 on success)
     */
    @Modifying
    @Query(REFRESH_LATEST)
    Mono<Long> refreshLatest(@Param("id") String id, @Param("ct") String ct,
                             @Param("lvi") String lvi, @Param("lvt") String lvt);

    // ── DB-generated UUID PK insert (changelog 008): id is OMITTED so Postgres fills it
    //    from the (gen_random_uuid())::text column DEFAULT; RETURNING id reads it back. A
    //    plain (non-@Modifying) @Query returning the new id. The supplied columns are exactly
    //    the non-id values the former save(new TubeSubscription(id, ...)) persisted (the
    //    download view's fields; thumbnail_url/synced_at keep their DB defaults — the Google
    //    sync view owns those). This is ONLY the fresh-INSERT branch of the find-then-write
    //    upsert — the in-place refreshLatest UPDATE is unchanged.
    String INSERT_RETURNING_ID = """
            INSERT INTO tube_subscription \
            (domain, user_subject, channel_id, channel_title, latest_video_id, \
             latest_video_title, created_at, updated_at) \
            VALUES (:domain, :userSubject, :channelId, :channelTitle, :latestVideoId, \
             :latestVideoTitle, :createdAt, :updatedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("userSubject") String userSubject,
                                   @Param("channelId") String channelId,
                                   @Param("channelTitle") String channelTitle,
                                   @Param("latestVideoId") String latestVideoId,
                                   @Param("latestVideoTitle") String latestVideoTitle,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("updatedAt") Instant updatedAt);

    // ── listForOwner: WHERE user_subject [AND domain] ORDER BY channel_title, channel_id
    Flux<TubeSubscription> findByUserSubjectOrderByChannelTitleAscChannelIdAsc(String userSubject);

    Flux<TubeSubscription> findByUserSubjectAndDomainOrderByChannelTitleAscChannelIdAsc(
            String userSubject, String domain);

    // ── findByChannel: WHERE user_subject AND channel_id [AND domain] -> first ──────
    Mono<TubeSubscription> findFirstByUserSubjectAndChannelId(String userSubject, String channelId);

    Mono<TubeSubscription> findFirstByUserSubjectAndChannelIdAndDomain(
            String userSubject, String channelId, String domain);
}
