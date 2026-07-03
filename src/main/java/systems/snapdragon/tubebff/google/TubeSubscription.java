package systems.snapdragon.tubebff.google;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — one of a connected user's subscribed YouTube
 * channels (schema in Liquibase {@code db/changelog/006-tube-subscription.xml}).
 * {@code domain} + {@code userSubject} scope it to the owning (brand,user); the
 * {@code channelId} is unique within that scope (the sync UPSERTs in place).
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
