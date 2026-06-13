package systems.snapdragon.tubebff.download;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_subscription} — the per-user subscribed-channel
 * content model that is the ENQUEUE SOURCE for the download work-queue (schema in
 * Liquibase {@code db/changelog/006-tube-subscription.xml}). Same
 * {@code DatabaseClient.sql(...).bind().map().all()} shape + app-generated UUID id +
 * domain-scoping convention as {@code TubeAccessRepository}.
 *
 * <p>The READS are OWNER + DOMAIN scoped: a user only ever resolves THEIR OWN
 * subscriptions within THEIR brand (the owner predicate {@code user_subject = :user} is
 * combined with the {@link DomainScope} brand predicate). The full Google-OAuth sync that
 * populates this table is a separate path; {@link #upsert} here is the minimal seam the
 * queue's enqueue path (and tests) use to record a subscription.
 */
@Repository
public class SubscriptionRepository {

    private final DatabaseClient db;

    public SubscriptionRepository(DatabaseClient db) {
        this.db = db;
    }

    private static final String COLS =
            "id, domain, user_subject, channel_id, channel_title, latest_video_id, "
            + "latest_video_title, created_at, updated_at";

    private static TubeSubscription map(Row row, RowMetadata meta) {
        return new TubeSubscription(
                row.get("id", String.class),
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                row.get("channel_id", String.class),
                row.get("channel_title", String.class),
                row.get("latest_video_id", String.class),
                row.get("latest_video_title", String.class),
                instant(row.get("created_at", OffsetDateTime.class)),
                instant(row.get("updated_at", OffsetDateTime.class)));
    }

    /**
     * The owner's subscribed channels WITHIN a brand — the enqueue source. OWNER + DOMAIN
     * scoped: only the named subject's rows in the given brand. A {@code null} domain is
     * the SUPERADMIN cross-domain bypass.
     */
    public Flux<TubeSubscription> listForOwner(String userSubject, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_subscription "
                        + "WHERE user_subject = :user" + DomainScope.andPredicate(domain)
                        + " ORDER BY channel_title, channel_id")
                .bind("user", userSubject);
        return DomainScope.bind(spec, domain).map(SubscriptionRepository::map).all();
    }

    /**
     * Idempotent insert/update of a subscription on its dedup triple
     * (domain, user_subject, channel_id) — the minimal seam tests + the sync use to
     * record a subscription. Find-then-insert (the H2-portable idiom; the dedup unique
     * index is the backstop on PG). On a re-record of the same channel, the latest video
     * fields are refreshed.
     */
    public Mono<TubeSubscription> upsert(String userSubject, String channelId, String channelTitle,
                                         String latestVideoId, String latestVideoTitle, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByChannel(userSubject, channelId, dom)
                .flatMap(existing -> db.sql("UPDATE tube_subscription SET channel_title = :ct, "
                                + "latest_video_id = :lvi, latest_video_title = :lvt, updated_at = now() "
                                + "WHERE id = :id")
                        .bind("id", existing.id())
                        .bind("ct", nz(channelTitle))
                        .bind("lvi", nz(latestVideoId))
                        .bind("lvt", nz(latestVideoTitle))
                        .fetch().rowsUpdated()
                        .thenReturn(new TubeSubscription(existing.id(), dom, userSubject, channelId,
                                channelTitle, latestVideoId, latestVideoTitle,
                                existing.createdAt(), Instant.now())))
                .switchIfEmpty(Mono.defer(() -> insert(userSubject, channelId, channelTitle,
                        latestVideoId, latestVideoTitle, dom)));
    }

    private Mono<TubeSubscription> insert(String userSubject, String channelId, String channelTitle,
                                          String latestVideoId, String latestVideoTitle, String dom) {
        String id = UUID.randomUUID().toString();
        return db.sql("INSERT INTO tube_subscription "
                        + "(id, domain, user_subject, channel_id, channel_title, latest_video_id, "
                        + " latest_video_title, created_at, updated_at) "
                        + "VALUES (:id, :dom, :user, :cid, :ct, :lvi, :lvt, now(), now())")
                .bind("id", id).bind("dom", dom).bind("user", userSubject).bind("cid", channelId)
                .bind("ct", nz(channelTitle)).bind("lvi", nz(latestVideoId)).bind("lvt", nz(latestVideoTitle))
                .fetch().rowsUpdated()
                .thenReturn(new TubeSubscription(id, dom, userSubject, channelId, channelTitle,
                        latestVideoId, latestVideoTitle, Instant.now(), Instant.now()));
    }

    private Mono<TubeSubscription> findByChannel(String userSubject, String channelId, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_subscription "
                        + "WHERE user_subject = :user AND channel_id = :cid"
                        + DomainScope.andPredicate(domain))
                .bind("user", userSubject).bind("cid", channelId);
        return DomainScope.bind(spec, domain).map(SubscriptionRepository::map).first();
    }

    // bind helpers — r2dbc-h2 rejects a raw null bind, so coerce optional text to "".
    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }

    @SuppressWarnings("unused")
    private static OffsetDateTime offset(Instant i) {
        return i == null ? null : i.atOffset(ZoneOffset.UTC);
    }
}
