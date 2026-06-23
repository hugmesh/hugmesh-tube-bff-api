package systems.snapdragon.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for {@code tube_download_job} — the download WORK-QUEUE
 * (schema in Liquibase {@code db/changelog/005-tube-download-queue.xml}). MATCHES the
 * snapdragon-federation-api exemplar: DERIVED finders where derivation suffices, plus
 * {@code @Query} (as {@code static final String} CONSTANTS, never inline literals) for
 * the guarded-CAS lifecycle transitions + the LIMITed claim-candidate read that
 * derivation cannot express.
 *
 * <p>The {@code state IN ('claimed','downloading')} guards and the literal target states
 * are spliced from {@link DownloadJob}'s {@code STATE_*} constants — compile-time
 * constant expressions, so the SQL stays an exact copy of the original literals.
 */
public interface DownloadJobR2dbcRepository extends R2dbcRepository<DownloadJob, String> {

    // ── claim-candidate read (LIMIT — derivation cannot express a runtime limit) ────
    String QUEUED_CANDIDATES =
            "SELECT * FROM tube_download_job WHERE state = '" + DownloadJob.STATE_QUEUED + "' "
            + "ORDER BY created_at, id LIMIT :lim";

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

    @Modifying
    @Query(CLAIM_ONE)
    Mono<Long> claimOne(@Param("id") String id, @Param("worker") String worker);

    String MARK_DOWNLOADING =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DOWNLOADING + "', "
            + "updated_at = now() WHERE id = :id AND claimed_by = :worker "
            + "AND state = '" + DownloadJob.STATE_CLAIMED + "'";

    @Modifying
    @Query(MARK_DOWNLOADING)
    Mono<Long> markDownloading(@Param("id") String id, @Param("worker") String worker);

    String MARK_DONE =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DONE + "', "
            + "bytes = :bytes, content_path = :path, updated_at = now() "
            + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
            + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')";

    @Modifying
    @Query(MARK_DONE)
    Mono<Long> markDone(@Param("id") String id, @Param("worker") String worker,
                        @Param("bytes") long bytes, @Param("path") String path);

    String MARK_FAILED =
            "UPDATE tube_download_job SET state = '" + DownloadJob.STATE_FAILED + "', "
            + "last_error = :err, updated_at = now() "
            + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
            + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')";

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
