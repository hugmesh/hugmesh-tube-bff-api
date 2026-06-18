package systems.snapdragon.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_download_job} row — one (domain, user_subject, video) the system
 * wants DOWNLOADED (schema in Liquibase {@code db/changelog/005-tube-download-queue.xml}).
 * The BFF owns the WORK-QUEUE; the future yt-dlp runner CronJob polls the internal
 * claim/report endpoints to do the actual download.
 *
 * <p>The job moves through a small state machine the repository CASes between:
 * <pre>
 *   queued -&gt; claimed -&gt; downloading -&gt; done
 *                                      -&gt; failed
 *   queued -&gt; skipped   (storage budget full at enqueue/claim — pause-on-full)
 * </pre>
 *
 * <ul>
 *   <li>{@code domain} — the brand the job belongs to, stamped SERVER-SIDE from the
 *       acting principal's validated-issuer brand (NEVER a request field). A scoped
 *       user/admin only ever touches their own brand's jobs; SUPERADMIN cross-domain.</li>
 *   <li>{@code userSubject} — the Casdoor subject who OWNS the job (the subscriber whose
 *       feed it came from); the owner-scope key for the user list/enqueue surface.</li>
 *   <li>{@code videoId} — the dedup key within (domain, user_subject): the same video is
 *       enqueued at most once (UNIQUE(domain, user_subject, video_id)).</li>
 *   <li>{@code state} / {@code claimedBy} / {@code claimedAt} / {@code attempts} /
 *       {@code lastError} — the queue lifecycle: a worker claims a 'queued' row (stamps
 *       claimed_by + claimed_at, state='claimed'), reports progress/result back.</li>
 *   <li>{@code bytes} / {@code contentPath} — set on {@code done}; the byte count feeds
 *       {@code tube_storage_usage}, the path locates the file on the content PVC.</li>
 * </ul>
 */
@Table("tube_download_job")
public record DownloadJob(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("channel_id") String channelId,
        @Column("video_id") String videoId,
        @Column("title") String title,
        @Column("state") String state,
        @Column("claimed_by") String claimedBy,
        @Column("claimed_at") Instant claimedAt,
        @Column("attempts") int attempts,
        @Column("last_error") String lastError,
        @Column("bytes") Long bytes,
        @Column("content_path") String contentPath,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt) implements Persistable<String> {

    @Override
    public String getId() {
        return id;
    }

    /** Always an INSERT (app-generated UUID id). The queue's lifecycle transitions are
     *  derived modifying CASes, never a {@code save()} of a read row, so {@code save()}
     *  is only ever a fresh insert. */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }

    /** Enqueued, awaiting a worker claim. */
    public static final String STATE_QUEUED = "queued";
    /** Claimed by exactly one worker (claimed_by stamped), not yet downloading. */
    public static final String STATE_CLAIMED = "claimed";
    /** A worker is actively downloading the content. */
    public static final String STATE_DOWNLOADING = "downloading";
    /** Download complete; bytes + content_path stamped, usage accounted. */
    public static final String STATE_DONE = "done";
    /** Download failed; last_error carries the reason (drives retry/GC). */
    public static final String STATE_FAILED = "failed";
    /** Not downloaded because the owner's storage budget was full at enqueue/claim
     *  (pause-on-full — the queue never spins/throw-loops on a full budget). */
    public static final String STATE_SKIPPED = "skipped";

    public boolean isQueued() {
        return STATE_QUEUED.equals(state);
    }
}
