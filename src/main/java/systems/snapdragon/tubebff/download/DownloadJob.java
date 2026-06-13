package systems.snapdragon.tubebff.download;

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
public record DownloadJob(
        String id,
        String domain,
        String userSubject,
        String channelId,
        String videoId,
        String title,
        String state,
        String claimedBy,
        Instant claimedAt,
        int attempts,
        String lastError,
        Long bytes,
        String contentPath,
        Instant createdAt,
        Instant updatedAt) {

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
