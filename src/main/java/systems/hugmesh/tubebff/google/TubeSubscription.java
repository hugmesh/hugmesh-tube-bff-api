package systems.hugmesh.tubebff.google;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — the Google-sync view of a connected user's
 * subscribed YouTube channel (title, thumbnail, last sync timestamp).
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml}. {@code domain} and
 * {@code userSubject} scope the row to the owning (brand, user); {@code channelId} is the
 * dedup key within that scope — the sync UPSERTs in place rather than duplicating.
 *
 * <p>Implements {@link Persistable}&lt;String&gt; with {@code isNew = true} because the PK
 * is an app-generated UUID; {@code save()} is therefore always an INSERT. The in-place
 * sync refresh is a constant-{@code @Query} partial UPDATE.
 *
 * <p>This record maps only a subset of {@code tube_subscription}'s columns (the ones the
 * Google sync writes); see the sibling
 * {@link systems.hugmesh.tubebff.download.TubeSubscription} for the download work-queue's
 * view of the same table (including {@code latest_video_id}/{@code latest_video_title},
 * which this sync does not populate).
 *
 * @see TubeSubscriptionRepository
 * @see TubeSubscriptionR2dbcRepository
 */
@Table("tube_subscription")
public record TubeSubscription(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("channel_id") String channelId,
        @Column("channel_title") String channelTitle,
        @Column("thumbnail_url") String thumbnailUrl,
        @Column("synced_at") Instant syncedAt) implements Persistable<String> {

    @Override
    public String getId() {
        return id;
    }

    /** Always an INSERT (DB-generated id, changelog 008). The in-place sync refresh is a
     *  constant-{@code @Query} partial UPDATE, never a {@code save()} of a read row. */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }
}
