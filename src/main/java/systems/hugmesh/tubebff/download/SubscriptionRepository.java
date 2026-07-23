package systems.hugmesh.tubebff.download;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for the {@code tube_subscription} per-user subscribed-channel
 * content model — the enqueue source for the download work-queue.
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml}. Refactored
 * (2026-06-18 data-access standard) from hand-written {@code DatabaseClient} raw SQL to
 * delegate to {@link SubscriptionR2dbcRepository} (derived finders + constant-{@code @Query}
 * partial UPDATE). Owner + domain scoping, find-then-write upsert idiom, ordering, and
 * latest-video refresh-on-re-record are unchanged.
 *
 * @see SubscriptionR2dbcRepository
 * @see TubeSubscription
 * @see DownloadJobService
 */
@Repository
public class SubscriptionRepository {

    private final SubscriptionR2dbcRepository repo;

    public SubscriptionRepository(SubscriptionR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * All subscribed channels for a user within a brand, ordered by channel title then id.
     * Domain-scoped for ADMIN callers; un-pinned (no domain predicate) for SUPERADMIN
     * {@code null}-domain bypass.
     *
     * @param userSubject the Casdoor subject of the owner
     * @param domain      the brand; {@code null}/blank activates the SUPERADMIN bypass
     * @return a {@code Flux} of {@link TubeSubscription} rows
     */
    public Flux<TubeSubscription> listForOwner(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByChannelTitleAscChannelIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByChannelTitleAscChannelIdAsc(userSubject, domain);
    }

    /**
     * Idempotent insert/update of a subscription on its dedup triple (domain, user_subject,
     * channel_id). Uses a find-then-write pattern that is H2 + Postgres portable. On a
     * re-record of the same channel the latest-video fields ({@code channelTitle},
     * {@code latestVideoId}, {@code latestVideoTitle}) are refreshed in-place; on a
     * first-record a new row is inserted with a generated UUID id.
     *
     * @param userSubject      the Casdoor subject of the owner
     * @param channelId        the YouTube channel id (dedup key)
     * @param channelTitle     the channel display title (nullable — coerced to "" if absent)
     * @param latestVideoId    the most-recent video id (nullable — coerced to "")
     * @param latestVideoTitle the most-recent video title (nullable — coerced to "")
     * @param domain           the brand; {@code null}/blank defaults to the platform default domain
     * @return a {@code Mono} emitting the saved or updated {@link TubeSubscription} row
     */
    public Mono<TubeSubscription> upsert(String userSubject, String channelId, String channelTitle,
                                         String latestVideoId, String latestVideoTitle, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByChannel(userSubject, channelId, dom)
                .flatMap(existing -> repo.refreshLatest(existing.id(), nz(channelTitle),
                                nz(latestVideoId), nz(latestVideoTitle))
                        .thenReturn(new TubeSubscription(existing.id(), dom, userSubject, channelId,
                                channelTitle, latestVideoId, latestVideoTitle,
                                existing.createdAt(), Instant.now())))
                .switchIfEmpty(Mono.defer(() -> insert(userSubject, channelId, channelTitle,
                        latestVideoId, latestVideoTitle, dom)));
    }

    private Mono<TubeSubscription> insert(String userSubject, String channelId, String channelTitle,
                                          String latestVideoId, String latestVideoTitle, String dom) {
        Instant now = Instant.now();
        // The id is DB-generated ((gen_random_uuid())::text DEFAULT, changelog 008): the INSERT
        // omits it and persists the nz()-coerced text (as the former save() did) and RETURNING id
        // hands back the generated id, which we render into the returned row (the same row shape
        // the former code returned — RAW caller values, not the nz()-coerced persisted ones).
        return repo.insertReturningId(dom, userSubject, channelId, nz(channelTitle),
                        nz(latestVideoId), nz(latestVideoTitle), now, now)
                .map(id -> new TubeSubscription(id, dom, userSubject, channelId,
                        channelTitle, latestVideoId, latestVideoTitle, now, now));
    }

    private Mono<TubeSubscription> findByChannel(String userSubject, String channelId, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubjectAndChannelId(userSubject, channelId)
                : repo.findFirstByUserSubjectAndChannelIdAndDomain(userSubject, channelId, domain);
    }

    // bind helpers — r2dbc-h2 rejects a raw null bind, so coerce optional text to "".
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
