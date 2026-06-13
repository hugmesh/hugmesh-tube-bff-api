package systems.snapdragon.tubebff.download;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;

/**
 * The download work-queue orchestration — the API the {@link TubeDownloadController} (user
 * surface) and the internal worker endpoint call.
 *
 * <p><b>SECURITY-CRITICAL OWNER + DOMAIN DERIVATION.</b> For every USER-facing operation
 * the owner ({@code user_subject}) AND the brand ({@code domain}) are derived SERVER-SIDE
 * from the validated JWT — owner from {@code jwt.getSubject()}, domain from the validated
 * issuer via {@link PrincipalDomain}. NEITHER is ever read from a request field, so user A
 * cannot list or enqueue jobs for user B, and cannot reach another brand's queue. This is
 * the {@code PersonalOwner} stance: FAIL-CLOSED — a principal with no usable JWT subject is
 * rejected, and (unlike the access-governance plane) there is NO SUPERADMIN null bypass on
 * the personal queue: a SUPERADMIN acts as themselves here (their own subject + domain),
 * never as another user.
 *
 * <p>The {@link #claim} / {@link #report} operations are the INTERNAL worker seam (the
 * future yt-dlp CronJob polls them). They take a {@code workerId} (NOT a user JWT) and are
 * mounted under a worker/service-principal-gated path — they MUST NOT be reachable by a
 * plain {@code ROLE_TUBE} user.
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
     * List the calling user's OWN download jobs in their OWN brand. Owner + domain are
     * server-derived from the JWT — a user can NEVER list another user's or another brand's
     * jobs.
     */
    public Flux<DownloadJob> listForOwner(Authentication auth) {
        Owner o = owner(auth);
        return jobs.listForOwner(o.subject(), o.domain());
    }

    /**
     * Enqueue download jobs from the calling user's subscriptions. For each subscribed
     * channel with a known latest video, enqueue a job (DEDUPED on video_id — re-running is
     * idempotent). PAUSE-ON-FULL: when the user's storage budget is already full, the job
     * is recorded as {@code skipped} instead of {@code queued} (never a throw-loop). Owner +
     * domain are server-derived from the JWT.
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
     * Atomically claim up to {@code n} queued jobs for {@code workerId} (the future
     * CronJob worker). PAUSE-ON-FULL is also honoured here: a claimed job whose OWNER is
     * over budget is immediately re-marked {@code skipped} (the worker should not download
     * it) — so a full user never has work actually downloaded even if a stale job sits
     * queued. INTERNAL: gated to a worker/service principal at the controller, NOT a user.
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
     * Report a worker's result for a job. {@code done} stamps bytes + content_path AND adds
     * the bytes to the owner's storage usage (the only place used_bytes grows); {@code
     * failed} stamps last_error; {@code downloading} marks progress. Guarded on the worker
     * owning the claim in the repo. INTERNAL: worker/service-principal-gated.
     */
    public Mono<DownloadJob> report(String jobId, String workerId, String result,
                                    long bytes, String contentPath, String error) {
        return jobs.findById(jobId).flatMap(job -> {
            String r = result == null ? "" : result.trim().toLowerCase();
            return switch (r) {
                case DownloadJob.STATE_DONE -> jobs.markDone(jobId, workerId, bytes, contentPath)
                        .flatMap(rows -> rows != null && rows > 0
                                // Account the bytes against the owner's budget ONLY when this
                                // worker's markDone actually landed (so a stale/lost report
                                // never double-counts).
                                ? usage.addUsage(job.userSubject(), job.domain(), bytes)
                                        .then(jobs.findById(jobId))
                                : jobs.findById(jobId));
                case DownloadJob.STATE_FAILED -> jobs.markFailed(jobId, workerId, error)
                        .then(jobs.findById(jobId));
                case DownloadJob.STATE_DOWNLOADING -> jobs.markDownloading(jobId, workerId)
                        .then(jobs.findById(jobId));
                default -> Mono.error(new IllegalArgumentException(
                        "result must be one of done|failed|downloading"));
            };
        });
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
