package systems.snapdragon.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for the {@code tube_download_job} download work-queue.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-download-queue.xml}. Follows the
 * snapdragon-federation-api exemplar: derived finders where derivation suffices, plus
 * constant-{@code @Query} strings (never inline literals) for the guarded-CAS lifecycle
 * transitions and the LIMIT-bounded claim-candidate read that derivation cannot express.
 *
 * <p>The {@code STATE_*} constants from {@link DownloadJob} are spliced into each SQL
 * string as compile-time constant expressions, ensuring the literals in SQL and in the
 * entity remain byte-identical and cannot drift.
 *
 * @see DownloadJobRepository
 * @see DownloadJob
 */
public interface DownloadJobR2dbcRepository extends R2dbcRepository<DownloadJob, String> {

    // ── claim-candidate read (LIMIT — derivation cannot express a runtime limit) ────
    String QUEUED_CANDIDATES =
            "SELECT * FROM tube_download_job WHERE state = '" + DownloadJob.STATE_QUEUED + "' "
            + "ORDER BY created_at, id LIMIT :lim";

    /**
     * Read up to {@code lim} of the oldest queued jobs (cross-domain) for the claim
     * batch. Ordered by {@code created_at, id} to favour FIFO. A LIMIT clause is required
     * which derivation cannot express, hence the constant {@code @Query}.
     *
     * @param lim the maximum number of candidate rows to return
     * @return a {@code Flux} of up to {@code lim} queued {@link DownloadJob} rows
     */
    @Query(QUEUED_CANDIDATES)
    Flux<DownloadJob> findQueuedCandidates(@Param("lim") int lim);

    // ── DB-generated UUID PK insert (changelog 008): id is OMITTED so Postgres fills it
    //    from the (gen_random_uuid())::text column DEFAULT; RETURNING id reads it back. A
    //    plain (non-@Modifying) @Query returning the new id. The supplied columns are exactly
    //    the non-id, non-null values the former save(new DownloadJob(id, ...)) persisted
    //    (claimed_by/claimed_at/last_error/bytes/content_path stay NULL as before; attempts
    //    starts 0; created_at/updated_at are the same app-stamped instant), so the queued row
    //    is BYTE-IDENTICAL except the id source. This is ONLY the fresh-INSERT branch — the
    //    enqueue() find-then-write dedup is unchanged. -->
    String INSERT_RETURNING_ID = """
            INSERT INTO tube_download_job \
            (domain, user_subject, channel_id, video_id, title, state, attempts, \
             created_at, updated_at) \
            VALUES (:domain, :userSubject, :channelId, :videoId, :title, :state, 0, \
             :createdAt, :updatedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("userSubject") String userSubject,
                                   @Param("channelId") String channelId,
                                   @Param("videoId") String videoId,
                                   @Param("title") String title,
                                   @Param("state") String state,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("updatedAt") Instant updatedAt);

    // ── guarded-CAS lifecycle transitions ──────────────────────────────────────────
    String CLAIM_ONE =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_CLAIMED + "', "
            + "claimed_by = :worker, claimed_at = now(), attempts = attempts + 1, "
            + "updated_at = now() WHERE id = :id AND state = '" + DownloadJob.STATE_QUEUED + "'";

    /**
     * Atomically CAS one job from {@code queued -> claimed} for a given worker, stamping
     * {@code claimed_by}, {@code claimed_at}, and incrementing {@code attempts}.
     *
     * @param id     the job id to claim
     * @param worker the worker identity string to stamp as {@code claimed_by}
     * @return a {@code Mono} emitting rows-updated (1 = won; 0 = lost race)
     */
    @Modifying
    @Query(CLAIM_ONE)
    Mono<Long> claimOne(@Param("id") String id, @Param("worker") String worker);

    String MARK_DOWNLOADING =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DOWNLOADING + "', "
            + "updated_at = now() WHERE id = :id AND claimed_by = :worker "
            + "AND state = '" + DownloadJob.STATE_CLAIMED + "'";

    /**
     * CAS {@code claimed -> downloading} for the worker that holds the claim. Guarded on
     * {@code claimed_by = :worker} so only the owning worker can advance the state.
     *
     * @param id     the job id
     * @param worker the worker that owns the claim
     * @return a {@code Mono} emitting rows-updated (1 = advanced; 0 = wrong state/worker)
     */
    @Modifying
    @Query(MARK_DOWNLOADING)
    Mono<Long> markDownloading(@Param("id") String id, @Param("worker") String worker);

    String MARK_DONE =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DONE + "', "
            + "bytes = :bytes, content_path = :path, updated_at = now() "
            + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
            + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')";

    /**
     * CAS {@code claimed|downloading -> done}, stamping {@code bytes} and
     * {@code content_path}. Guarded on the worker owning the claim.
     *
     * @param id     the job id
     * @param worker the worker that owns the claim
     * @param bytes  the downloaded file size in bytes
     * @param path   the content path on the PVC (e.g. {@code /acme/alice/videos/vid.mp4})
     * @return a {@code Mono} emitting rows-updated (1 = completed; 0 = wrong state/worker)
     */
    @Modifying
    @Query(MARK_DONE)
    Mono<Long> markDone(@Param("id") String id, @Param("worker") String worker,
                        @Param("bytes") long bytes, @Param("path") String path);

    String MARK_FAILED =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_FAILED + "', "
            + "last_error = :err, updated_at = now() "
            + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
            + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')";

    /**
     * CAS {@code claimed|downloading -> failed}, stamping {@code last_error}. Guarded on
     * the worker owning the claim.
     *
     * @param id     the job id
     * @param worker the worker that owns the claim
     * @param err    the error message to record in {@code last_error}
     * @return a {@code Mono} emitting rows-updated (1 = failed; 0 = wrong state/worker)
     */
    @Modifying
    @Query(MARK_FAILED)
    Mono<Long> markFailed(@Param("id") String id, @Param("worker") String worker,
                          @Param("err") String err);

    // ── reads: owner [+ domain] scoped, created_at DESC, id ─────────────────────────
    Flux<DownloadJob> findByUserSubjectOrderByCreatedAtDescIdAsc(String userSubject);

    Flux<DownloadJob> findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(
            String userSubject, String domain);

    // ── dedup lookup: WHERE user_subject AND video_id [AND domain] -> first ──────────
    Mono<DownloadJob> findFirstByUserSubjectAndVideoId(String userSubject, String videoId);

    Mono<DownloadJob> findFirstByUserSubjectAndVideoIdAndDomain(
            String userSubject, String videoId, String domain);
}
