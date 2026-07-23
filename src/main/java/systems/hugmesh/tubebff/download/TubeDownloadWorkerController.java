package systems.hugmesh.tubebff.download;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * The INTERNAL worker seam for the download work-queue — the endpoints the FUTURE yt-dlp
 * downloader CronJob polls to claim queued jobs and report results. Mounted under
 * {@code /bff/tube/internal/**}, which {@link systems.hugmesh.tubebff.config.SecurityConfig}
 * gates to {@code ROLE_TUBE_WORKER} (a service/mTLS principal) ONLY.
 *
 * <p><b>SECURITY-CRITICAL: NOT a user surface.</b> The method-level
 * {@link #WORKER_ONLY} @PreAuthorize requires {@code ROLE_TUBE_WORKER} and is defence in
 * depth on top of the path gate. A plain {@code ROLE_TUBE} user (or any human role —
 * USER / MOD / ADMIN / SUPERADMIN) is DENIED: claiming and reporting jobs is a machine
 * operation, and SUPERADMIN is deliberately NOT given a hierarchy edge to the worker role
 * (a human must never be able to claim/complete another user's download job). The claim
 * is atomic (each job to exactly one worker); pause-on-full is honoured at claim time.
 */
@Tag(name = "Tube Download Worker (internal)", description = "INTERNAL claim/report seam for "
        + "the future yt-dlp downloader CronJob. ROLE_TUBE_WORKER (service principal) ONLY — "
        + "NOT reachable by ROLE_TUBE users or any human role.")
@RestController
@RequestMapping("/bff/tube/internal/download-jobs")
@Validated
public class TubeDownloadWorkerController {

    /** WORKER_ONLY — the internal claim/report seam is a SERVICE principal operation. The
     *  worker role is deliberately OUTSIDE the human role hierarchy: no USER/MOD/ADMIN/
     *  SUPERADMIN reaches it (a human must never claim/complete another user's job). */
    public static final String WORKER_ONLY = "hasRole('TUBE_WORKER')";

    private final DownloadJobService service;

    public TubeDownloadWorkerController(DownloadJobService service) {
        this.service = service;
    }

    /**
     * Claim up to {@code body.limit()} queued jobs for the given worker. Each job is
     * atomically CAS'd to exactly one worker; pause-on-full is honoured at claim time
     * (over-budget jobs are skipped and excluded from the returned list).
     *
     * @param body the claim request — {@code workerId} and {@code limit}
     * @return a {@code Mono} emitting the list of claimed {@link TubeDownloadDto.Job} rows
     */
    @Operation(operationId = "claimDownloadJobs",
            summary = "WORKER claims up to N queued jobs (atomic — each job to exactly "
            + "one worker; pause-on-full honoured). ROLE_TUBE_WORKER only.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Claimed jobs (may be fewer than limit or empty)"),
        @ApiResponse(responseCode = "400", description = "Validation failure on request body"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid credentials"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_TUBE_WORKER"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(WORKER_ONLY)
    @PostMapping("/claim")
    public Mono<TubeDownloadDto.JobList> claim(@Valid @RequestBody TubeDownloadDto.ClaimRequest body) {
        return service.claim(body.workerId(), body.limit())
                .map(TubeDownloadDto.Job::of)
                .collectList()
                .map(TubeDownloadDto.JobList::new);
    }

    /**
     * Report a result for a previously claimed job. Routes on {@code body.result()}:
     * {@code done} stamps bytes + path and accounts storage usage; {@code failed} stamps
     * the error; {@code downloading} marks progress. Each CAS is guarded on the worker
     * owning the claim.
     *
     * @param body the report request — jobId, workerId, result, bytes, contentPath, error
     * @return a {@code Mono} emitting the updated {@link TubeDownloadDto.Job}
     */
    @Operation(operationId = "reportDownloadJob",
            summary = "WORKER reports a job result (done stamps bytes+path and accounts "
            + "storage; failed stamps the error; downloading marks progress). "
            + "ROLE_TUBE_WORKER only.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Updated job row"),
        @ApiResponse(responseCode = "400", description = "Validation failure or unknown result value"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid credentials"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_TUBE_WORKER"),
        @ApiResponse(responseCode = "404", description = "Job id not found"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(WORKER_ONLY)
    @PostMapping("/report")
    public Mono<TubeDownloadDto.Job> report(@Valid @RequestBody TubeDownloadDto.ReportRequest body) {
        return service.report(body.jobId(), body.workerId(), body.result(),
                        body.bytes(), body.contentPath(), body.error())
                .map(TubeDownloadDto.Job::of);
    }
}
