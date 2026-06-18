package systems.snapdragon.tubebff.google;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_subscription} — a connected user's mirrored
 * YouTube channels (schema in Liquibase {@code db/changelog/006-tube-subscription.xml}).
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link TubeSubscriptionR2dbcRepository}
 * (Spring Data R2DBC). Owner-scoped, single-domain; the find-then-write idempotent UPSERT
 * (update-in-place → insert-if-absent) and ordering are UNCHANGED.
 */
@Repository
public class TubeSubscriptionRepository {

    private final TubeSubscriptionR2dbcRepository repo;

    public TubeSubscriptionRepository(TubeSubscriptionR2dbcRepository repo) {
        this.repo = repo;
    }

    /** A user's subscribed channels in their brand. Owner+domain scoped. */
    public Flux<TubeSubscription> listForOwner(String domain, String userSubject) {
        return repo.findByDomainAndUserSubjectOrderByChannelTitleAscChannelIdAsc(domain, userSubject);
    }

    /**
     * Idempotent UPSERT of one channel for an owner in their brand: update the
     * title/thumbnail/synced_at in place if the (domain,user,channel) row exists, else
     * insert a new row (app-generated id). Returns the rows-updated count of the write that
     * landed (always &gt;=1 on success).
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
        String id = UUID.randomUUID().toString();
        TubeSubscription row = new TubeSubscription(id, domain, userSubject, channelId,
                channelTitle, thumbnailUrl, Instant.now());
        return repo.save(row).thenReturn(1L);
    }
}
