package systems.snapdragon.tubebff.download;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code tube_subscription} — the per-user subscribed-channel
 * content model that is the ENQUEUE SOURCE for the download work-queue (schema in
 * Liquibase {@code db/changelog/006-tube-subscription.xml}).
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link SubscriptionR2dbcRepository}
 * (Spring Data R2DBC). The OWNER + DOMAIN scoping, the find-then-write upsert idiom,
 * ordering, and the latest-video refresh-on-re-record are UNCHANGED.
 */
@Repository
public class SubscriptionRepository {

    private final SubscriptionR2dbcRepository repo;

    public SubscriptionRepository(SubscriptionR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The owner's subscribed channels WITHIN a brand — the enqueue source. Owner + domain
     *  scoped (un-pinned for the SUPERADMIN {@code null}-domain bypass). */
    public Flux<TubeSubscription> listForOwner(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByChannelTitleAscChannelIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByChannelTitleAscChannelIdAsc(userSubject, domain);
    }

    /**
     * Idempotent insert/update of a subscription on its dedup triple
     * (domain, user_subject, channel_id). Find-then-write (H2-portable). On a re-record of
     * the same channel, the latest video fields are refreshed.
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
