package net.hugmesh.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — the per-user subscribed YouTube channel record
 * that is the enqueue source for the yt-dlp download work-queue.
 *
 * <p>Schema: Liquibase {@code db/changelog/006-tube-subscription.xml} +
 * {@code 007-...-download-fields.xml}. For each subscribed channel with a known latest
 * video the work-queue enqueues a download job deduped on (user_subject, channel_id,
 * latest_video_id). The Google-OAuth sync that populates the base {@code tube_subscription}
 * row from the user's YouTube account lives in {@code google/SubscriptionsSyncService}, but
 * that sync currently only writes the columns modeled by the sibling
 * {@link net.hugmesh.tubebff.google.TubeSubscription} record (id, domain,
 * user_subject, channel_id, channel_title, thumbnail_url, synced_at) — it never populates
 * {@code latest_video_id}/{@code latest_video_title}. No writer in this codebase currently
 * sets those two columns; populating them (e.g. from a per-channel "latest upload" lookup)
 * is an unimplemented gap, not something handled elsewhere.
 *
 * <p>This record maps only a subset of {@code tube_subscription}'s columns (the ones the
 * download work-queue reads); see the sibling
 * {@link net.hugmesh.tubebff.google.TubeSubscription} for the columns the Google sync
 * writes.
 *
 * <p>Domain-scoped: {@code domain} stamped server-side from the validated JWT issuer;
 * composite natural key (domain, user_subject, channel_id).
 *
 * <p>Implements {@link Persistable}&lt;String&gt; with {@code isNew = true} because the PK
 * is an app-generated UUID; {@code save()} is therefore always an INSERT. The in-place
 * latest-video refresh is a constant-{@code @Query} partial UPDATE in
 * {@link SubscriptionR2dbcRepository#refreshLatest}, never a {@code save()}.
 *
 * @see SubscriptionRepository
 * @see SubscriptionR2dbcRepository
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

    /** Always an INSERT (DB-generated id, changelog 008). The in-place latest-video refresh is a
     *  derived/constant-{@code @Query} partial UPDATE, never a {@code save()} of a read
     *  row, so {@code save()} is only ever a fresh insert. */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }
}
