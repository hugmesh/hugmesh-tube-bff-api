package systems.snapdragon.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — a per-user subscribed YouTube channel (schema
 * in Liquibase {@code db/changelog/006-tube-subscription.xml}). This is the minimal
 * content model the download work-queue reads as its ENQUEUE SOURCE: for each of the
 * owner's subscribed channels with a known latest video, the queue enqueues a download
 * job (deduped on the video id).
 *
 * <p>The full Google-OAuth subscriptions sync that POPULATES this table from the user's
 * YouTube account is the separate Google-connect path; here it is just the model the
 * enqueue reads. DOMAIN-scoped: {@code domain} stamped SERVER-SIDE from the validated
 * issuer; one row per (domain, user_subject, channel_id).
 */
@Table("tube_subscription")
public record TubeSubscription(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("channel_id") String channelId,
        @Column("channel_title") String channelTitle,
        @Column("latest_video_id") String latestVideoId,
        @Column("latest_video_title") String latestVideoTitle,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt) implements Persistable<String> {

    @Override
    public String getId() {
        return id;
    }

    /** Always an INSERT (app-generated UUID id). The in-place latest-video refresh is a
     *  derived/constant-{@code @Query} partial UPDATE, never a {@code save()} of a read
     *  row, so {@code save()} is only ever a fresh insert. */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }
}
