package systems.snapdragon.tubebff.download;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_download_job} — the download WORK-QUEUE (schema
 * in Liquibase {@code db/changelog/005-tube-download-queue.xml}). Same hand-written-SQL +
 * app-generated UUID id + domain-scoping convention as {@code TubeAccessRepository}.
 *
 * <p>The queue is a small state machine the writes here CAS between:
 * <pre>
 *   queued -&gt; claimed -&gt; downloading -&gt; done | failed
 *   queued -&gt; skipped   (storage budget full at enqueue/claim — pause-on-full)
 * </pre>
 *
 * <p><b>DEDUP.</b> {@link #enqueue} is idempotent on the dedup triple
 * (domain, user_subject, video_id): a find-then-insert (the H2-portable idiom) backed by
 * the {@code uq_tube_download_job_dedup} unique index (the race backstop on PG). Enqueuing
 * the same video twice yields exactly ONE row.
 *
 * <p><b>CLAIM (FOR-UPDATE-SKIP-LOCKED-equivalent).</b> {@link #claimOne} is a guarded CAS:
 * {@code UPDATE ... SET state='claimed', claimed_by=:worker WHERE id=:id AND
 * state='queued'} stamping the worker. The {@code AND state='queued'} guard means EXACTLY
 * ONE writer wins the transition for a given row (rows-updated 1 = this worker claimed it,
 * 0 = another worker already did) — the row-level CAS serializes concurrent claimers, so a
 * job is claimed by exactly one worker under concurrency WITHOUT a SELECT...FOR UPDATE that
 * H2 doesn't honour the same way Postgres does. {@link #claimBatch} drives N of these from
 * the oldest queued rows.
 *
 * <p>The READS are OWNER + DOMAIN scoped ({@link #listForOwner}): a user only ever resolves
 * THEIR OWN jobs within THEIR brand; a {@code null} domain is the SUPERADMIN cross-domain
 * bypass.
 */
@Repository
public class DownloadJobRepository {

    private final DatabaseClient db;

    public DownloadJobRepository(DatabaseClient db) {
        this.db = db;
    }

    private static final String COLS =
            "id, domain, user_subject, channel_id, video_id, title, state, claimed_by, "
            + "claimed_at, attempts, last_error, bytes, content_path, created_at, updated_at";

    private static DownloadJob map(Row row, RowMetadata meta) {
        Integer attempts = row.get("attempts", Integer.class);
        return new DownloadJob(
                row.get("id", String.class),
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                row.get("channel_id", String.class),
                row.get("video_id", String.class),
                row.get("title", String.class),
                row.get("state", String.class),
                row.get("claimed_by", String.class),
                instant(row.get("claimed_at", OffsetDateTime.class)),
                attempts == null ? 0 : attempts,
                row.get("last_error", String.class),
                row.get("bytes", Long.class),
                row.get("content_path", String.class),
                instant(row.get("created_at", OffsetDateTime.class)),
                instant(row.get("updated_at", OffsetDateTime.class)));
    }

    // ── enqueue (idempotent on the dedup triple) ───────────────────────────────

    /**
     * Idempotently enqueue a download job for (domain, user_subject, video_id). If a job
     * for that triple already exists (any state), it is returned UNCHANGED (dedup — the
     * same video is never enqueued twice). Otherwise a new {@code queued} row is inserted.
     * The {@code domain} is the owner's brand (defaulted to the platform {@code default}
     * domain for an unscoped/SUPERADMIN write so a stamped row always carries a concrete
     * brand).
     */
    public Mono<DownloadJob> enqueue(String userSubject, String channelId, String videoId,
                                     String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insertQueued(userSubject, channelId, videoId, title, dom)));
    }

    /**
     * Enqueue a row DIRECTLY in a terminal {@code skipped} state — used by the
     * pause-on-full path when the owner's storage budget is already full at enqueue time:
     * the job is RECORDED (so the user sees it was skipped) but never claimed. Idempotent
     * on the dedup triple like {@link #enqueue}.
     */
    public Mono<DownloadJob> enqueueSkipped(String userSubject, String channelId, String videoId,
                                            String title, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return findByVideo(userSubject, videoId, dom)
                .switchIfEmpty(Mono.defer(() ->
                        insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_SKIPPED)));
    }

    private Mono<DownloadJob> insertQueued(String userSubject, String channelId, String videoId,
                                           String title, String dom) {
        return insert(userSubject, channelId, videoId, title, dom, DownloadJob.STATE_QUEUED);
    }

    private Mono<DownloadJob> insert(String userSubject, String channelId, String videoId,
                                     String title, String dom, String state) {
        String id = UUID.randomUUID().toString();
        return db.sql("INSERT INTO tube_download_job "
                        + "(id, domain, user_subject, channel_id, video_id, title, state, "
                        + " attempts, created_at, updated_at) "
                        + "VALUES (:id, :dom, :user, :cid, :vid, :title, :state, 0, now(), now())")
                .bind("id", id).bind("dom", dom).bind("user", userSubject)
                .bind("cid", nz(channelId)).bind("vid", videoId).bind("title", nz(title))
                .bind("state", state)
                .fetch().rowsUpdated()
                .thenReturn(new DownloadJob(id, dom, userSubject, channelId, videoId, title,
                        state, null, null, 0, null, null, null, Instant.now(), Instant.now()));
    }

    // ── claim (FOR-UPDATE-SKIP-LOCKED-equivalent guarded CAS) ──────────────────

    /**
     * Atomically claim up to {@code limit} of the OLDEST queued jobs for {@code workerId}.
     * Reads the candidate queued ids (cross-domain — the worker is an internal service that
     * processes every brand's queue), then CASes each via {@link #claimOne}; only the rows
     * this worker actually won (the guarded UPDATE landed) are emitted. Under concurrency
     * the per-row CAS guarantees each job goes to exactly one worker.
     */
    public Flux<DownloadJob> claimBatch(String workerId, int limit) {
        int n = limit <= 0 ? 0 : limit;
        if (n == 0) return Flux.empty();
        return queuedIds(n)
                .concatMap(id -> claimOne(id, workerId));   // concatMap = serialize the CAS attempts
    }

    /** The oldest {@code limit} queued job ids (claim candidates), cross-domain. */
    private Flux<String> queuedIds(int limit) {
        return db.sql("SELECT id FROM tube_download_job WHERE state = '" + DownloadJob.STATE_QUEUED
                        + "' ORDER BY created_at, id LIMIT :lim")
                .bind("lim", limit)
                .map((row, meta) -> row.get("id", String.class))
                .all();
    }

    /**
     * Guarded CAS claim of ONE job for a worker: {@code UPDATE ... SET state='claimed',
     * claimed_by=:worker, claimed_at=now(), attempts=attempts+1 WHERE id=:id AND
     * state='queued'}. Returns the now-claimed row IFF this worker won the transition
     * (rows-updated 1); empty when another worker already claimed it (rows-updated 0) — so
     * a job is claimed by EXACTLY ONE worker under concurrency.
     */
    public Mono<DownloadJob> claimOne(String id, String workerId) {
        return db.sql("UPDATE tube_download_job SET state = '" + DownloadJob.STATE_CLAIMED + "', "
                        + "claimed_by = :worker, claimed_at = now(), attempts = attempts + 1, "
                        + "updated_at = now() WHERE id = :id AND state = '" + DownloadJob.STATE_QUEUED + "'")
                .bind("id", id).bind("worker", workerId)
                .fetch().rowsUpdated()
                .flatMap(rows -> rows != null && rows > 0 ? findById(id) : Mono.empty());
    }

    // ── state transitions (markDownloading / markDone / markFailed) ────────────

    /** CAS {@code claimed -> downloading} (the worker started the transfer). */
    public Mono<Long> markDownloading(String id, String workerId) {
        return db.sql("UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DOWNLOADING + "', "
                        + "updated_at = now() WHERE id = :id AND claimed_by = :worker "
                        + "AND state = '" + DownloadJob.STATE_CLAIMED + "'")
                .bind("id", id).bind("worker", workerId)
                .fetch().rowsUpdated();
    }

    /**
     * Mark a job {@code done}, stamping the downloaded {@code bytes} + {@code contentPath}.
     * Guarded on the worker owning the claim so a stale worker cannot complete another's
     * job. Returns rows-updated (1 = this worker completed it). The byte count is added to
     * the owner's {@code tube_storage_usage} by the SERVICE after this lands.
     */
    public Mono<Long> markDone(String id, String workerId, long bytes, String contentPath) {
        return db.sql("UPDATE tube_download_job SET state = '" + DownloadJob.STATE_DONE + "', "
                        + "bytes = :bytes, content_path = :path, updated_at = now() "
                        + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
                        + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')")
                .bind("id", id).bind("worker", workerId)
                .bind("bytes", bytes).bind("path", nz(contentPath))
                .fetch().rowsUpdated();
    }

    /** Mark a job {@code failed}, stamping {@code last_error}. Guarded on the worker
     *  owning the claim. */
    public Mono<Long> markFailed(String id, String workerId, String error) {
        return db.sql("UPDATE tube_download_job SET state = '" + DownloadJob.STATE_FAILED + "', "
                        + "last_error = :err, updated_at = now() "
                        + "WHERE id = :id AND claimed_by = :worker AND state IN ('"
                        + DownloadJob.STATE_CLAIMED + "', '" + DownloadJob.STATE_DOWNLOADING + "')")
                .bind("id", id).bind("worker", workerId).bind("err", nz(error))
                .fetch().rowsUpdated();
    }

    // ── reads ──────────────────────────────────────────────────────────────────

    /**
     * The download jobs OWNED by a user WITHIN a brand — the owner-scoped list surface.
     * OWNER ({@code user_subject = :user}) + DOMAIN scoped: a user only ever sees THEIR OWN
     * jobs in THEIR brand; a {@code null} domain is the SUPERADMIN cross-domain bypass.
     */
    public Flux<DownloadJob> listForOwner(String userSubject, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_download_job "
                        + "WHERE user_subject = :user" + DomainScope.andPredicate(domain)
                        + " ORDER BY created_at DESC, id")
                .bind("user", userSubject);
        return DomainScope.bind(spec, domain).map(DownloadJobRepository::map).all();
    }

    /** Look up a job by id (no scope — internal use after a CAS; the worker endpoints are
     *  service-principal-gated, the user endpoints never call this). */
    public Mono<DownloadJob> findById(String id) {
        return db.sql("SELECT " + COLS + " FROM tube_download_job WHERE id = :id")
                .bind("id", id).map(DownloadJobRepository::map).first();
    }

    private Mono<DownloadJob> findByVideo(String userSubject, String videoId, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_download_job "
                        + "WHERE user_subject = :user AND video_id = :vid"
                        + DomainScope.andPredicate(domain))
                .bind("user", userSubject).bind("vid", videoId);
        return DomainScope.bind(spec, domain).map(DownloadJobRepository::map).first();
    }

    // bind helpers — r2dbc-h2 rejects a raw null bind, so coerce optional text to "".
    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
