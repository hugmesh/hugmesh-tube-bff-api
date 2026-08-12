package net.hugmesh.tubebff.download;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.tubebff.access.TubeAccessGuard;

/**
 * The USER-facing download work-queue surface — list the caller's own jobs and enqueue jobs
 * from their subscriptions. Mounted under {@code /bff/tube/downloads}.
 *
 * <h2>Security</h2>
 *
 * <p><b>Default-deny use gate (first).</b> Every handler calls
 * {@link TubeAccessGuard#assertCanUse} before touching the queue. A principal without an
 * active {@code tube_access} use grant, or under an active ban, receives 403 — the bare
 * {@code ROLE_TUBE} floor does NOT confer queue access (SUPERADMIN is exempt inside the
 * guard).
 *
 * <p><b>Owner + brand server-derived.</b> {@link DownloadJobService} derives the owner
 * subject + brand from the validated JWT — user A can never list or enqueue jobs for user B,
 * and no request field can forge a cross-user or cross-brand scope.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *   Caller              │ Endpoints                        │ Outcome
 *   ────────────────────┼──────────────────────────────────┼────────────────────────────
 *   ROLE_TUBE (granted) │ GET /downloads, POST /downloads  │ own jobs only
 *   ROLE_TUBE (banned)  │ any                              │ 403 (ban > grant)
 *   ROLE_TUBE (no grant)│ any                              │ 403 (default-deny)
 *   unauthenticated     │ any                              │ 401
 * </pre>
 *
 * @see TubeAccessGuard
 * @see DownloadJobService
 */
@Tag(name = "Tube Downloads", description = "The user's download work-queue: list own jobs + "
        + "enqueue from subscriptions. Default-deny use (TubeAccessGuard) enforced first; "
        + "owner + brand are server-derived from the JWT (no cross-user/cross-brand access).")
@RestController
@RequestMapping("/bff/tube/downloads")
public class TubeDownloadController {

    /** The authenticated floor for the user surface. The exact use decision (an active
     *  grant AND NOT an active ban, SUPERADMIN exempt) is enforced programmatically by
     *  {@link TubeAccessGuard#assertCanUse} in each handler — a static SpEL cannot consult
     *  the DB for a per-principal grant/ban. */
    private static final String AUTHENTICATED = "isAuthenticated()";

    private final DownloadJobService service;
    private final TubeAccessGuard useGate;

    public TubeDownloadController(DownloadJobService service, TubeAccessGuard useGate) {
        this.service = service;
        this.useGate = useGate;
    }

    /**
     * List the calling user's own download jobs. Owner + brand are server-derived; the
     * default-deny use gate is enforced first.
     *
     * @param auth the authenticated user's JWT
     * @return a {@code Mono} emitting a {@link TubeDownloadDto.JobList} (may be empty)
     */
    @Operation(operationId = "listDownloadJobs",
            summary = "List the calling user's OWN download jobs (owner + brand "
            + "server-derived). Default-deny use enforced first.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Job list (may be empty)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "No active use grant or active ban"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @GetMapping
    public Mono<TubeDownloadDto.JobList> list(Authentication auth) {
        return useGate.assertCanUse(auth)
                .thenMany(service.listForOwner(auth))
                .map(TubeDownloadDto.Job::of)
                .collectList()
                .map(TubeDownloadDto.JobList::new);
    }

    /**
     * Enqueue download jobs from the calling user's subscriptions. Idempotent/deduped on
     * the (domain, user_subject, video_id) triple. PAUSE-ON-FULL: when the budget is
     * exhausted, new work is recorded as {@code skipped} rather than thrown. Owner + brand
     * are server-derived; the default-deny use gate is enforced first.
     *
     * @param auth the authenticated user's JWT
     * @return a {@code Mono} emitting a {@link TubeDownloadDto.JobList} of created/existing
     *         jobs (including any newly skipped ones)
     */
    @Operation(operationId = "enqueueDownloadJobs",
            summary = "Enqueue download jobs from the calling user's subscriptions "
            + "(deduped; pause-on-full marks new work skipped when the storage budget is "
            + "full). Owner + brand server-derived. Default-deny use enforced first.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Enqueued (or existing) job list"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "No active use grant or active ban"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(AUTHENTICATED)
    @PostMapping
    public Mono<TubeDownloadDto.JobList> enqueue(Authentication auth) {
        return useGate.assertCanUse(auth)
                .thenMany(service.enqueueFromSubscriptions(auth))
                .map(TubeDownloadDto.Job::of)
                .collectList()
                .map(TubeDownloadDto.JobList::new);
    }
}
