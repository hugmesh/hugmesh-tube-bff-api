package systems.hugmesh.tubebff.google;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for the {@code tube_subscription} mirrored YouTube channels
 * table — the Google-sync view used by {@link SubscriptionsSyncService}.
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml}. Refactored
 * (2026-06-18 data-access standard) from hand-written {@code DatabaseClient} raw SQL to
 * delegate to {@link TubeSubscriptionR2dbcRepository} (derived finder + constant-{@code
 * @Query} partial UPDATE). Owner-scoped, single-domain; the find-then-write idempotent
 * UPSERT (update-in-place → insert-if-absent) and ordering are unchanged.
 *
 * @see TubeSubscriptionR2dbcRepository
 * @see TubeSubscription
 */
@Repository
public class TubeSubscriptionRepository {

    private final TubeSubscriptionR2dbcRepository repo;

    public TubeSubscriptionRepository(TubeSubscriptionR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * All subscribed channels for a user in their brand, ordered by channel title then id.
     * Owner + domain scoped (always pinned — no SUPERADMIN bypass).
     *
     * @param domain      the brand
     * @param userSubject the Casdoor subject of the owner
     * @return a {@code Flux} of {@link TubeSubscription} rows
     */
    public Flux<TubeSubscription> listForOwner(String domain, String userSubject) {
        return repo.findByDomainAndUserSubjectOrderByChannelTitleAscChannelIdAsc(domain, userSubject);
    }

    /**
     * Idempotent UPSERT of one subscribed channel for an owner in their brand. Uses a
     * find-then-write pattern: if the (domain, user, channel_id) row exists, updates the
     * title, thumbnail, and {@code synced_at} in place; otherwise inserts a new row with
     * an app-generated UUID id.
     *
     * @param domain       the brand
     * @param userSubject  the Casdoor subject of the owner
     * @param channelId    the YouTube channel id (dedup key)
     * @param channelTitle the current channel title
     * @param thumbnailUrl the channel thumbnail URL
     * @return a {@code Mono} emitting rows-written (always &ge; 1 on success)
     * @implNote This is the only production writer of {@code tube_subscription}. It does not
     *     set {@code latest_video_id}/{@code latest_video_title} — those columns belong to the
     *     download work-queue's view of this table (see
     *     {@link systems.hugmesh.tubebff.download.TubeSubscription}) and currently have no
     *     writer anywhere in the codebase. As a result, {@code DownloadJobService
     *     #enqueueFromSubscriptions} — which filters on a non-blank {@code latestVideoId} —
     *     can never enqueue a job for a subscription synced through this path. Populating the
     *     latest-video fields (e.g. from a per-channel "latest upload" lookup during sync) is
     *     an unimplemented gap, tracked as follow-up work rather than fixed here.
     */
    public Mono<Long> upsert(String domain, String userSubject, String channelId,
                             String channelTitle, String thumbnailUrl) {
        return repo.syncUpdate(domain, userSubject, channelId, channelTitle, thumbnailUrl)
                .flatMap(updated -> updated > 0
                        ? Mono.just(updated)
                        : insert(domain, userSubject, channelId, channelTitle, thumbnailUrl));
    }

    private Mono<Long> insert(String domain, String userSubject, String channelId,
                              String channelTitle, String thumbnailUrl) {
        // The id is DB-generated ((gen_random_uuid())::text DEFAULT, changelog 008): the INSERT
        // omits it; RETURNING id confirms the fresh row landed and we report rows-updated 1L
        // (the same contract the former save().thenReturn(1L) returned).
        return repo.insertReturningId(domain, userSubject, channelId, channelTitle, thumbnailUrl,
                        Instant.now())
                .thenReturn(1L);
    }
}
