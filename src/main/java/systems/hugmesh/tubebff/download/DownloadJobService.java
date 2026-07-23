package systems.hugmesh.tubebff.download;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.tubebff.security.PrincipalDomain;

/**
 * Download work-queue orchestration — the API {@link TubeDownloadController} (user surface)
 * and {@link TubeDownloadWorkerController} (internal worker) delegate to.
 *
 * <h2>Security-critical owner + domain derivation</h2>
 *
 * <p>For every USER-facing operation the owner ({@code user_subject}) AND the brand
 * ({@code domain}) are derived SERVER-SIDE from the validated JWT — owner from
 * {@code jwt.getSubject()}, domain from the validated issuer via {@link PrincipalDomain}.
 * NEITHER is ever read from a request field: user A cannot list or enqueue jobs for user B,
 * and cannot reach another brand's queue. FAIL-CLOSED: a principal with no usable JWT
 * subject is rejected. Unlike the access-governance plane there is NO SUPERADMIN null bypass
 * on the personal queue — a SUPERADMIN acts as themselves (own subject + domain, defaulted
 * to {@code default}), never as another user.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *   Caller              │ Operations allowed
 *   ────────────────────┼─────────────────────────────────────────────────────
 *   ROLE_TUBE (granted) │ listForOwner, enqueueFromSubscriptions (own jobs only)
 *   ROLE_TUBE_WORKER    │ claim, report (machine operation — no user JWT)
 *   ROLE_ADMIN/SUPER    │ setBudget via TubeStorageBudgetController (separate)
 * </pre>
 *
 * @see TubeDownloadController
 * @see TubeDownloadWorkerController
 * @see DownloadJobRepository
 * @see StorageUsageService
 */
@Service
public class DownloadJobService {

    private static final Logger log = LoggerFactory.getLogger(DownloadJobService.class);

    private final DownloadJobRepository jobs;
    private final SubscriptionRepository subscriptions;
    private final StorageUsageService usage;
    private final PrincipalDomain principalDomain;

    public DownloadJobService(DownloadJobRepository jobs, SubscriptionRepository subscriptions,
                              StorageUsageService usage, PrincipalDomain principalDomain) {
        this.jobs = jobs;
        this.subscriptions = subscriptions;
        this.usage = usage;
        this.principalDomain = principalDomain;
    }

    // ── USER surface (owner + domain server-derived) ───────────────────────────

    /**
     * List the calling user's own download jobs in their own brand. Owner + domain are
     * server-derived from the JWT — a user can never list another user's or another brand's
     * jobs.
     *
     * @param auth the authenticated user's JWT; subject + domain derived server-side
     * @return a {@code Flux} of the caller's {@link DownloadJob} rows, newest first
     * @throws IllegalStateException if the principal has no usable JWT subject (fail-closed)
     */
    public Flux<DownloadJob> listForOwner(Authentication auth) {
        Owner o = owner(auth);
        return jobs.listForOwner(o.subject(), o.domain());
    }

    /**
     * Enqueue download jobs from the calling user's subscriptions. For each subscribed
     * channel with a known latest video id, enqueues a job deduped on
     * {@code (domain, user_subject, video_id)} — re-running is idempotent. PAUSE-ON-FULL:
     * when the user's storage budget is already exhausted the job is recorded as
     * {@code skipped} instead of {@code queued} (never a throw-loop). Owner + domain are
     * server-derived from the JWT.
     *
     * @param auth the authenticated user's JWT; subject + domain derived server-side
     * @return a {@code Flux} of the created or pre-existing {@link DownloadJob} rows
     * @throws IllegalStateException if the principal has no usable JWT subject (fail-closed)
     */
    public Flux<DownloadJob> enqueueFromSubscriptions(Authentication auth) {
        Owner o = owner(auth);
        String subject = o.subject();
        String domain = o.domain();
        // Resolve the full/not-full state ONCE per enqueue run (pause-on-full is a coarse
        // per-user gate — we never spin re-checking it per row).
        return usage.isFull(subject, domain).flatMapMany(full ->
                subscriptions.listForOwner(subject, domain)
                        .filter(s -> s.latestVideoId() != null && !s.latestVideoId().isBlank())
                        .concatMap(s -> full
                                ? jobs.enqueueSkipped(subject, s.channelId(), s.latestVideoId(),
                                        s.latestVideoTitle(), domain)
                                : jobs.enqueue(subject, s.channelId(), s.latestVideoId(),
                                        s.latestVideoTitle(), domain))
                        .doOnComplete(() -> log.info("[tube-download] enqueueFromSubscriptions "
                                + "for {} (domain={}, full={})", subject, domain, full)));
    }

    // ── INTERNAL worker seam (workerId, NOT a user JWT) ────────────────────────

    /**
     * Atomically claim up to {@code n} queued jobs for {@code workerId}. PAUSE-ON-FULL is
     * also honoured at claim time: a claimed job whose owner is over budget is immediately
     * re-marked {@code failed} (budget-full sentinel) and excluded from the returned batch,
     * so a full user never has work downloaded even if a stale job sits queued. INTERNAL:
     * gated to a worker/service principal; NOT reachable by a plain {@code ROLE_TUBE} user.
     *
     * @param workerId the worker identity string (stamped as {@code claimed_by})
     * @param n        the maximum number of jobs to claim; 0 or negative returns empty
     * @return a {@code Flux} of claimed {@link DownloadJob} rows that the worker should
     *         download (jobs whose owners are over budget are excluded)
     */
    public Flux<DownloadJob> claim(String workerId, int n) {
        return jobs.claimBatch(workerId, n)
                .concatMap(job -> usage.isFull(job.userSubject(), job.domain()).flatMap(full -> {
                    if (full) {
                        // PAUSE-ON-FULL: the owner is over budget — re-mark the just-claimed
                        // job 'failed' (skipped-for-budget) and DROP it from the worker's
                        // batch so it is never actually downloaded. Never a throw/spin-loop.
                        return jobs.markFailed(job.id(), workerId, "storage budget full (skipped)")
                                .then(Mono.<DownloadJob>empty());
                    }
                    return Mono.just(job);   // headroom — hand the job to the worker
                }));
    }

    /**
     * Report a worker's result for a previously claimed job. Routes on {@code result}:
     * <ul>
     *   <li>{@code done} — stamps bytes + content_path AND adds the bytes to the owner's
     *       storage usage (the only place {@code used_bytes} grows); returns the updated
     *       row.</li>
     *   <li>{@code failed} — stamps {@code last_error}; returns the updated row.</li>
     *   <li>{@code downloading} — marks progress; returns the updated row.</li>
     * </ul>
     * Each CAS is guarded on the worker owning the claim in the repo. INTERNAL:
     * worker/service-principal-gated.
     *
     * @param jobId       the job to update
     * @param workerId    the worker that holds the claim (verified in the CAS guard)
     * @param result      one of {@code done}, {@code failed}, or {@code downloading}
     * @param bytes       the downloaded byte count (only meaningful for {@code done})
     * @param contentPath the content-PVC path (only meaningful for {@code done})
     * @param error       the error message (only meaningful for {@code failed})
     * @return a {@code Mono} emitting the updated {@link DownloadJob}
     * @throws IllegalArgumentException if {@code result} is not one of the three known values
     */
    public Mono<DownloadJob> report(String jobId, String workerId, String result,
                                    long bytes, String contentPath, String error) {
        // Look up the claimed job, then dispatch the worker's result to the appropriate state machine.
        return jobs.findById(jobId)
                .flatMap(job -> applyWorkerResult(job, jobId, workerId, result, bytes, contentPath, error));
    }

    /**
     * Dispatch a worker's result to the correct state transition — done, failed, or downloading.
     * Accounting bytes against the owner's storage budget is done ONLY when markDone lands,
     * so a stale or lost report never double-counts.
     */
    private Mono<DownloadJob> applyWorkerResult(DownloadJob job, String jobId, String workerId,
                                                String result, long bytes, String contentPath,
                                                String error) {
        String r = result == null ? "" : result.trim().toLowerCase();
        return switch (r) {
            // DONE: stamp bytes + path, then account the bytes against the owner's budget.
            case DownloadJob.STATE_DONE -> jobs.markDone(jobId, workerId, bytes, contentPath)
                    .flatMap(rows -> rows != null && rows > 0
                            // Account the bytes against the owner's budget ONLY when this
                            // worker's markDone actually landed (so a stale/lost report
                            // never double-counts).
                            ? usage.addUsage(job.userSubject(), job.domain(), bytes)
                                    .then(jobs.findById(jobId))
                            : jobs.findById(jobId));
            // FAILED: stamp last_error and return the updated job.
            case DownloadJob.STATE_FAILED -> jobs.markFailed(jobId, workerId, error)
                    .then(jobs.findById(jobId));
            // DOWNLOADING: mark progress and return the updated job.
            case DownloadJob.STATE_DOWNLOADING -> jobs.markDownloading(jobId, workerId)
                    .then(jobs.findById(jobId));
            default -> Mono.error(new IllegalArgumentException(
                    "result must be one of done|failed|downloading"));
        };
    }

    // ── owner derivation (the security-critical seam) ──────────────────────────

    /**
     * Derive the (subject, domain) owner pair from the validated JWT — FAIL-CLOSED. The
     * subject is {@code jwt.getSubject()} and the domain is the issuer-derived brand via
     * {@link PrincipalDomain#forScope}. A principal with no usable JWT subject is rejected
     * (no anonymous/forge-able owner). There is NO SUPERADMIN null-domain bypass here: on
     * the PERSONAL queue a SUPERADMIN acts as themselves (their own subject + the issuer
     * domain, defaulted to {@code default} for the cross-domain super-role), never as
     * another user.
     */
    private Owner owner(Authentication auth) {
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt) || jwt.getSubject() == null
                || jwt.getSubject().isBlank()) {
            throw new IllegalStateException("a tube download owner requires an authenticated JWT subject");
        }
        String subject = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        // forScope returns null for SUPERADMIN (the cross-domain access bypass) — but the
        // personal queue is NEVER cross-domain, so a SUPERADMIN is pinned to the platform
        // default domain (their own personal queue), never a null = all-brands scope.
        if (domain == null) {
            domain = DomainRegistry.DEFAULT_DOMAIN;
        }
        return new Owner(subject, domain);
    }

    private record Owner(String subject, String domain) {}
}
