package net.hugmesh.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_download_job} row — one (domain, user_subject, video) the system
 * wants downloaded by the yt-dlp CronJob worker.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-download-queue.xml}. The BFF owns the
 * WORK-QUEUE; the future yt-dlp runner CronJob polls the internal claim/report endpoints
 * ({@link TubeDownloadWorkerController}) to do the actual download.
 *
 * <h2>State machine</h2>
 *
 * <pre>
 *   queued ──► claimed ──► downloading ──► done
 *                                      └──► failed
 *   queued ──► skipped   (storage budget full at enqueue/claim — pause-on-full)
 * </pre>
 *
 * <p>Each transition is a guarded CAS in {@link DownloadJobR2dbcRepository}. A lost race
 * (rows-updated = 0) means another worker already won that transition.
 *
 * <h2>Key columns</h2>
 *
 * <ul>
 *   <li>{@code domain} — brand, stamped SERVER-SIDE from the validated JWT issuer
 *       (never a request field). A scoped user sees only their brand's jobs; SUPERADMIN
 *       is cross-domain.</li>
 *   <li>{@code userSubject} — the Casdoor subject who owns the job (the subscriber whose
 *       feed it came from); the owner-scope key for the user list/enqueue surface.</li>
 *   <li>{@code videoId} — the dedup key within (domain, user_subject); the same video is
 *       enqueued at most once ({@code UNIQUE(domain, user_subject, video_id)}).</li>
 *   <li>{@code state} / {@code claimedBy} / {@code claimedAt} / {@code attempts} /
 *       {@code lastError} — queue lifecycle fields.</li>
 *   <li>{@code bytes} / {@code contentPath} — set on {@code done}; the byte count is
 *       added to {@code tube_storage_usage}, the path locates the file on the content
 *       PVC.</li>
 * </ul>
 *
 * @see DownloadJobRepository
 * @see DownloadJobService
 * @see TubeDownloadWorkerController
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

    /** Always an INSERT (DB-generated id, changelog 008). The queue's lifecycle transitions are
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

    /**
     * Returns {@code true} when this job is in the {@link #STATE_QUEUED} state — eligible
     * to be claimed by a worker.
     *
     * @return {@code true} iff {@code state.equals(STATE_QUEUED)}
     */
    public boolean isQueued() {
        return STATE_QUEUED.equals(state);
    }
}
