package systems.snapdragon.tubebff.google;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_subscription} — a connected user's mirrored
 * YouTube channels (schema in Liquibase {@code db/changelog/006-tube-subscription.xml}).
 *
 * <p><b>Owner-scoped, single-domain.</b> Every read/write keys on BOTH {@code domain} AND
 * {@code user_subject}; a user only ever reads/writes THEIR OWN subscriptions in THEIR
 * brand (no cross-brand bypass).
 *
 * <p><b>Portable idempotent UPSERT.</b> {@link #upsert} does a find-then-write
 * (update-by-(domain,user,channel) → insert-if-absent) rather than a dialect-specific
 * {@code ON CONFLICT}, so the H2 slice store and Postgres behave identically and the
 * UNIQUE(domain,user_subject,channel_id) constraint is the race backstop.
 */
@Repository
public class TubeSubscriptionRepository {

    private final DatabaseClient db;

    public TubeSubscriptionRepository(DatabaseClient db) {
        this.db = db;
    }

    private static final String COLS =
            "id, domain, user_subject, channel_id, channel_title, thumbnail_url, synced_at";

    private static TubeSubscription map(Row row, RowMetadata meta) {
        return new TubeSubscription(
                row.get("id", String.class),
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                row.get("channel_id", String.class),
                row.get("channel_title", String.class),
                row.get("thumbnail_url", String.class),
                instant(row.get("synced_at", OffsetDateTime.class)));
    }

    /** A user's subscribed channels in their brand, newest-synced first. Owner+domain
     *  scoped. */
    public Flux<TubeSubscription> listForOwner(String domain, String userSubject) {
        return db.sql("SELECT " + COLS + " FROM tube_subscription "
                        + "WHERE domain = :domain AND user_subject = :user "
                        + "ORDER BY channel_title, channel_id")
                .bind("domain", domain).bind("user", userSubject)
                .map(TubeSubscriptionRepository::map).all();
    }

    /**
     * Idempotent UPSERT of one channel for an owner in their brand: update the
     * title/thumbnail/synced_at in place if the (domain,user,channel) row exists, else
     * insert a new row (app-generated id). Returns the rows-updated count of the write
     * that landed (always &gt;=1 on success).
     */
    public Mono<Long> upsert(String domain, String userSubject, String channelId,
                             String channelTitle, String thumbnailUrl) {
        return updateExisting(domain, userSubject, channelId, channelTitle, thumbnailUrl)
                .flatMap(updated -> updated > 0
                        ? Mono.just(updated)
                        : insert(domain, userSubject, channelId, channelTitle, thumbnailUrl));
    }

    private Mono<Long> updateExisting(String domain, String userSubject, String channelId,
                                      String channelTitle, String thumbnailUrl) {
        DatabaseClient.GenericExecuteSpec spec = db.sql(
                        "UPDATE tube_subscription SET channel_title = :title, "
                        + "thumbnail_url = :thumb, synced_at = now() "
                        + "WHERE domain = :domain AND user_subject = :user AND channel_id = :chan")
                .bind("domain", domain).bind("user", userSubject).bind("chan", channelId);
        spec = bindNullable(spec, "title", channelTitle);
        spec = bindNullable(spec, "thumb", thumbnailUrl);
        return spec.fetch().rowsUpdated();
    }

    private Mono<Long> insert(String domain, String userSubject, String channelId,
                              String channelTitle, String thumbnailUrl) {
        String id = UUID.randomUUID().toString();
        DatabaseClient.GenericExecuteSpec spec = db.sql(
                        "INSERT INTO tube_subscription "
                        + "(id, domain, user_subject, channel_id, channel_title, thumbnail_url, synced_at) "
                        + "VALUES (:id, :domain, :user, :chan, :title, :thumb, now())")
                .bind("id", id)
                .bind("domain", domain).bind("user", userSubject).bind("chan", channelId);
        spec = bindNullable(spec, "title", channelTitle);
        spec = bindNullable(spec, "thumb", thumbnailUrl);
        return spec.fetch().rowsUpdated();
    }

    private static DatabaseClient.GenericExecuteSpec bindNullable(
            DatabaseClient.GenericExecuteSpec spec, String name, String value) {
        return value == null ? spec.bindNull(name, String.class) : spec.bind(name, value);
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
