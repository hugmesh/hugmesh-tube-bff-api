package systems.snapdragon.tubebff.download;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_download_job} — the download WORK-QUEUE (schema
 * in Liquibase {@code db/changelog/005-tube-download-queue.xml}).
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link DownloadJobR2dbcRepository}
 * (Spring Data R2DBC: DERIVED finders + constant-{@code @Query} guarded CASes), matching
 * the snapdragon-federation-api exemplar. The public surface, the dedup/find-then-insert
 * idiom, the per-row guarded-CAS claim, the lifecycle transitions, ordering, and
 * domain-scoping are UNCHANGED.
 */
@Repository
public class DownloadJobRepository {

    private final DownloadJobR2dbcRepository repo;

    public DownloadJobRepository(DownloadJobR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── enqueue (idempotent on the dedup triple) ───────────────────────────────

    /**
     * Idempotently enqueue a download job for (domain, user_subject, video_id). If a job
     * for that triple already exists (any state), it is returned UNCHANGED (dedup).
     * Otherwise a new {@code queued} row is inserted.
     */
    public Mono<DownloadJob> enqueue(String userSubject, String channelId, String videoId,
                                     String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_QUEUED)));
    }

    /**
     * Enqueue a row DIRECTLY in a terminal {@code skipped} state (pause-on-full at
     * enqueue time). Idempotent on the dedup triple like {@link #enqueue}.
     */
    public Mono<DownloadJob> enqueueSkipped(String userSubject, String channelId, String videoId,
                                            String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_SKIPPED)));
    }

    private Mono<DownloadJob> insert(String userSubject, String channelId, String videoId,
                                     String title, String dom, String state) {
        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        DownloadJob row = new DownloadJob(id, dom, userSubject, nz(channelId), videoId, nz(title),
                state, null, null, 0, null, null, null, now, now);
        return repo.save(row).thenReturn(row);
    }

    // ── claim (FOR-UPDATE-SKIP-LOCKED-equivalent guarded CAS) ──────────────────

    /**
     * Atomically claim up to {@code limit} of the OLDEST queued jobs for {@code workerId}.
     * Reads the candidate queued ids (cross-domain), then CASes each via {@link #claimOne};
     * only the rows this worker actually won are emitted.
     */
    public Flux<DownloadJob> claimBatch(String workerId, int limit) {
        int n = limit <= 0 ? 0 : limit;
        if (n == 0) return Flux.empty();
        return repo.findQueuedCandidates(n)
                .map(DownloadJob::id)
                .concatMap(id -> claimOne(id, workerId));   // concatMap = serialize the CAS attempts
    }

    /**
     * Guarded CAS claim of ONE job for a worker. Returns the now-claimed row IFF this
     * worker won the transition (rows-updated 1); empty when another worker already
     * claimed it (rows-updated 0).
     */
    public Mono<DownloadJob> claimOne(String id, String workerId) {
        return repo.claimOne(id, workerId)
                .flatMap(rows -> rows != null && rows > 0 ? findById(id) : Mono.empty());
    }

    // ── state transitions (markDownloading / markDone / markFailed) ────────────

    /** CAS {@code claimed -> downloading} (the worker started the transfer). */
    public Mono<Long> markDownloading(String id, String workerId) {
        return repo.markDownloading(id, workerId);
    }

    /** Mark a job {@code done}, stamping {@code bytes} + {@code contentPath}. Guarded on
     *  the worker owning the claim. Returns rows-updated (1 = this worker completed it). */
    public Mono<Long> markDone(String id, String workerId, long bytes, String contentPath) {
        return repo.markDone(id, workerId, bytes, nz(contentPath));
    }

    /** Mark a job {@code failed}, stamping {@code last_error}. Guarded on the worker. */
    public Mono<Long> markFailed(String id, String workerId, String error) {
        return repo.markFailed(id, workerId, nz(error));
    }

    // ── reads ──────────────────────────────────────────────────────────────────

    /** The download jobs OWNED by a user WITHIN a brand — owner + domain scoped. */
    public Flux<DownloadJob> listForOwner(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByCreatedAtDescIdAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByCreatedAtDescIdAsc(userSubject, domain);
    }

    /** Look up a job by id (no scope — internal use after a CAS). */
    public Mono<DownloadJob> findById(String id) {
        return repo.findById(id);
    }

    private Mono<DownloadJob> findByVideo(String userSubject, String videoId, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubjectAndVideoId(userSubject, videoId)
                : repo.findFirstByUserSubjectAndVideoIdAndDomain(userSubject, videoId, domain);
    }

    // bind helpers — r2dbc-h2 rejects a raw null bind, so coerce optional text to "".
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
