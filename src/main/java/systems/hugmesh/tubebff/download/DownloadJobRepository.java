package systems.hugmesh.tubebff.download;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for the {@code tube_download_job} download work-queue.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-download-queue.xml}. Refactored
 * (2026-06-18 data-access standard) from hand-written {@code DatabaseClient} raw SQL to
 * delegate to {@link DownloadJobR2dbcRepository} (derived finders + constant-{@code @Query}
 * guarded CASes). Public surface, dedup/find-then-insert idiom, per-row guarded-CAS claim,
 * lifecycle transitions, ordering, and domain-scoping are unchanged.
 *
 * <h2>Concurrency model</h2>
 *
 * <p>The claim path uses a guarded CAS: each job is read as a candidate, then a single
 * UPDATE guarded on {@code state = 'queued'} stamps exactly one worker. A rows-updated
 * count of 0 means another worker won the race; that candidate is silently skipped.
 *
 * @see DownloadJobR2dbcRepository
 * @see DownloadJobService
 * @see DownloadJob
 */
@Repository
public class DownloadJobRepository {

    private final DownloadJobR2dbcRepository repo;

    public DownloadJobRepository(DownloadJobR2dbcRepository repo) {
        this.repo = repo;
    }

    // ---- Enqueue (idempotent on the dedup triple) ----

    /**
     * Idempotently enqueue a download job for {@code (domain, userSubject, videoId)}.
     * If a job for that triple already exists (any state), it is returned UNCHANGED
     * (dedup — the UNIQUE constraint is the race backstop). Otherwise a new
     * {@code queued} row is inserted. The {@code domain} must already be a concrete
     * brand (unscoped values are pinned to {@link DomainRegistry#DEFAULT_DOMAIN} before
     * this call or by the caller).
     *
     * @param userSubject the Casdoor subject of the subscriber who owns the job
     * @param channelId   the YouTube channel id the video belongs to
     * @param videoId     the YouTube video id (dedup key within the triple)
     * @param title       the video title at enqueue time; may be {@code null}
     * @param domain      the owning brand (must be concrete, not null/blank)
     * @return a {@code Mono} emitting the existing or newly-created {@link DownloadJob}
     */
    public Mono<DownloadJob> enqueue(String userSubject, String channelId, String videoId,
                                     String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_QUEUED)));
    }

    /**
     * Enqueue a row directly in the {@code skipped} terminal state when the owner's
     * storage budget is full at enqueue time (pause-on-full). Idempotent on the dedup
     * triple: if a job already exists in any state, it is returned unchanged.
     *
     * @param userSubject the Casdoor subject of the subscriber who owns the job
     * @param channelId   the YouTube channel id
     * @param videoId     the YouTube video id (dedup key)
     * @param title       the video title; may be {@code null}
     * @param domain      the owning brand (must be concrete)
     * @return a {@code Mono} emitting the existing or newly-created skipped job
     */
    public Mono<DownloadJob> enqueueSkipped(String userSubject, String channelId, String videoId,
                                            String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_SKIPPED)));
    }

    /**
     * Insert a new job row with the given state. The id is DB-generated
     * ({@code (gen_random_uuid())::text DEFAULT}, changelog 008) and returned via
     * {@code RETURNING id}; {@link DownloadJob#isNew()} always returns {@code true} so
     * Spring Data performs an INSERT rather than a SELECT-then-UPDATE.
     *
     * @param userSubject the job owner's Casdoor subject
     * @param channelId   the source channel id (coerced to empty string if null)
     * @param videoId     the video id (dedup key)
     * @param title       the video title (coerced to empty string if null)
     * @param dom         the concrete brand (already resolved by the caller)
     * @param state       the initial state constant (e.g. {@link DownloadJob#STATE_QUEUED})
     * @return a {@code Mono} emitting the newly inserted {@link DownloadJob}
     */
    private Mono<DownloadJob> insert(String userSubject, String channelId, String videoId,
                                     String title, String dom, String state) {
        Instant now = Instant.now();
        // The id is DB-generated ((gen_random_uuid())::text DEFAULT, changelog 008): the
        // INSERT omits it and RETURNING id hands back the generated id, which we render into
        // the returned row (every other field unchanged from the former app-minted insert).
        return repo.insertReturningId(dom, userSubject, nz(channelId), videoId, nz(title), state, now, now)
                .map(id -> new DownloadJob(id, dom, userSubject, nz(channelId), videoId, nz(title),
                        state, null, null, 0, null, null, null, now, now));
    }

    // ---- Claim (FOR-UPDATE-SKIP-LOCKED-equivalent guarded CAS) ----

    /**
     * Atomically claim up to {@code limit} of the OLDEST queued jobs for {@code workerId}.
     * Reads the candidate queued ids (FIFO, cross-domain), then CASes each via
     * {@link #claimOne}; only the rows this worker actually won (rows-updated 1) are
     * emitted. CAS attempts are serialised ({@code concatMap}) to avoid a stampede.
     *
     * @param workerId a unique identifier for the claiming worker instance
     * @param limit    the maximum number of jobs to claim in this batch; &lt;= 0 is a no-op
     * @return a {@code Flux} of the claimed {@link DownloadJob} rows
     */
    public Flux<DownloadJob> claimBatch(String workerId, int limit) {
        var n = limit <= 0 ? 0 : limit;
        if (n == 0) return Flux.empty();
        return repo.findQueuedCandidates(n)
                .map(DownloadJob::id)
                .concatMap(id -> claimOne(id, workerId));   // concatMap = serialize the CAS attempts
    }

    /**
     * Guarded CAS claim of ONE job for a worker: {@code queued -> claimed}. Returns the
     * now-claimed row IFF this worker won the transition (rows-updated 1); empty when
     * another worker already claimed it (rows-updated 0).
     *
     * @param id       the UUID of the job to claim
     * @param workerId the unique worker identifier (stamped as {@code claimed_by})
     * @return a {@code Mono} emitting the claimed {@link DownloadJob}, or empty on a race
     */
    public Mono<DownloadJob> claimOne(String id, String workerId) {
        return repo.claimOne(id, workerId)
                .flatMap(rows -> rows != null && rows > 0 ? findById(id) : Mono.empty());
    }

    // ---- State transitions (markDownloading / markDone / markFailed) ----

    /**
     * CAS {@code claimed -> downloading}: the worker signals it started the content
     * transfer stream. Guarded on {@code claimed_by = workerId}.
     *
     * @param id       the job UUID
     * @param workerId the claiming worker's identifier (must match {@code claimed_by})
     * @return a {@code Mono} emitting the rows-updated count (1 = success, 0 = guard miss)
     */
    public Mono<Long> markDownloading(String id, String workerId) {
        return repo.markDownloading(id, workerId);
    }

    /**
     * Mark a job {@code done}, stamping {@code bytes} and {@code contentPath}. Guarded on
     * the worker owning the claim. Accepts both {@code claimed} and {@code downloading}
     * source states.
     *
     * @param id          the job UUID
     * @param workerId    the claiming worker's identifier
     * @param bytes       the byte count of the downloaded content
     * @param contentPath the path to the content file on the content PVC
     * @return a {@code Mono} emitting the rows-updated count (1 = success)
     */
    public Mono<Long> markDone(String id, String workerId, long bytes, String contentPath) {
        return repo.markDone(id, workerId, bytes, nz(contentPath));
    }

    /**
     * Mark a job {@code failed}, stamping {@code last_error}. Guarded on the worker
     * owning the claim.
     *
     * @param id       the job UUID
     * @param workerId the claiming worker's identifier
     * @param error    the error message to stamp (coerced to empty string if null)
     * @return a {@code Mono} emitting the rows-updated count (1 = success)
     */
    public Mono<Long> markFailed(String id, String workerId, String error) {
        return repo.markFailed(id, workerId, nz(error));
    }

    // ---- Reads ----

    /**
     * All download jobs owned by a user within a brand — owner + domain scoped. A
     * {@code null}/blank domain is the SUPERADMIN cross-domain bypass (all brands).
     *
     * @param userSubject the Casdoor subject of the job owner
     * @param domain      the owning brand; {@code null}/blank = SUPERADMIN (no predicate)
     * @return a {@code Flux} of the owner's jobs, newest first
     */
    public Flux<DownloadJob> listForOwner(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByCreatedAtDescIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(userSubject, domain);
    }

    /**
     * Look up a job by id (no scope — used internally after a CAS claim to read back the
     * full claimed row).
     *
     * @param id the UUID primary key
     * @return a {@code Mono} emitting the {@link DownloadJob}, or empty if not found
     */
    public Mono<DownloadJob> findById(String id) {
        return repo.findById(id);
    }

    /**
     * Dedup lookup: does a job for this (user, video, domain) triple already exist?
     * Used by {@link #enqueue} / {@link #enqueueSkipped} before inserting.
     */
    private Mono<DownloadJob> findByVideo(String userSubject, String videoId, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubjectAndVideoId(userSubject, videoId)
                : repo.findFirstByUserSubjectAndVideoIdAndDomain(userSubject, videoId, domain);
    }

    // ---- Bind helpers ----

    /**
     * Coerce a nullable string to empty string. R2DBC-H2 rejects a raw {@code null} bind
     * for text columns, so optional text fields are coerced to {@code ""} before binding.
     *
     * @param s the nullable string
     * @return {@code s} when non-null; {@code ""} when null
     */
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
