package systems.snapdragon.tubebff.google;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for the {@code tube_subscription} table — the Google-sync
 * view of a connected user's YouTube channels (thumbnail + synced_at).
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml}. Owner-scoped,
 * single-domain (no SUPERADMIN bypass). Follows the federation exemplar: a derived
 * owner+domain finder plus one constant-{@code @Query} for the in-place sync UPDATE that
 * a partial-update derivation cannot express.
 *
 * @see TubeSubscriptionRepository
 * @see TubeSubscription
 */
public interface TubeSubscriptionR2dbcRepository extends R2dbcRepository<TubeSubscription, String> {

    String SYNC_UPDATE =
            "UPDATE tube_subscription SET channel_title = :title, "
            + "thumbnail_url = :thumb, synced_at = now() "
            + "WHERE domain = :domain AND user_subject = :user AND channel_id = :chan";

    /**
     * In-place refresh of a subscription row's title, thumbnail, and {@code synced_at}
     * timestamp. Returns 0 when the (domain, user, channel) row does not yet exist —
     * the caller ({@link TubeSubscriptionRepository#upsert}) inserts on a 0 return.
     *
     * @param domain the brand
     * @param user   the Casdoor subject of the owner
     * @param chan   the YouTube channel id
     * @param title  the current channel title
     * @param thumb  the channel thumbnail URL
     * @return a {@code Mono} emitting rows-updated (1 on update, 0 when row absent)
     */
    @Modifying
    @Query(SYNC_UPDATE)
    Mono<Long> syncUpdate(@Param("domain") String domain, @Param("user") String user,
                          @Param("chan") String chan, @Param("title") String title,
                          @Param("thumb") String thumb);

    // ── DB-generated UUID PK insert (changelog 008): id is OMITTED so Postgres fills it
    //    from the (gen_random_uuid())::text column DEFAULT; RETURNING id reads it back. A
    //    plain (non-@Modifying) @Query returning the new id. The supplied columns are exactly
    //    the non-id values the former save(new TubeSubscription(id, ...)) persisted (the
    //    Google-sync view's fields; latest_video_*/created_at/updated_at keep their DB defaults
    //    — the download view owns those). This is ONLY the insert-if-absent branch of the
    //    update-then-insert upsert — the in-place syncUpdate UPDATE is unchanged.
    String INSERT_RETURNING_ID = """
            INSERT INTO tube_subscription \
            (domain, user_subject, channel_id, channel_title, thumbnail_url, synced_at) \
            VALUES (:domain, :userSubject, :channelId, :channelTitle, :thumbnailUrl, :syncedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("userSubject") String userSubject,
                                   @Param("channelId") String channelId,
                                   @Param("channelTitle") String channelTitle,
                                   @Param("thumbnailUrl") String thumbnailUrl,
                                   @Param("syncedAt") Instant syncedAt);

    /** A user's subscribed channels in their brand, ORDER BY channel_title, channel_id.
     *  Owner + domain scoped (always pinned). */
    Flux<TubeSubscription> findByDomainAndUserSubjectOrderByChannelTitleAscChannelIdAsc(
            String domain, String userSubject);
}
