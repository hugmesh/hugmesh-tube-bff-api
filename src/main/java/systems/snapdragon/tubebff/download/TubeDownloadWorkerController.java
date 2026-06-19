package systems.snapdragon.tubebff.download;

import io.swagger.v3.oas.annotations.Operation;
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
 * {@code /bff/tube/internal/**}, which {@link systems.snapdragon.tubebff.config.SecurityConfig}
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

    @Operation(operationId = "claimDownloadJobs",
            summary = "WORKER claims up to N queued jobs (atomic — each job to exactly "
            + "one worker; pause-on-full honoured). ROLE_TUBE_WORKER only.")
    @PreAuthorize(WORKER_ONLY)
    @PostMapping("/claim")
    public Mono<TubeDownloadDto.JobList> claim(@Valid @RequestBody TubeDownloadDto.ClaimRequest body) {
        return service.claim(body.workerId(), body.limit())
                .map(TubeDownloadDto.Job::of)
                .collectList()
                .map(TubeDownloadDto.JobList::new);
    }

    @Operation(operationId = "reportDownloadJob",
            summary = "WORKER reports a job result (done stamps bytes+path and accounts "
            + "storage; failed stamps the error; downloading marks progress). "
            + "ROLE_TUBE_WORKER only.")
    @PreAuthorize(WORKER_ONLY)
    @PostMapping("/report")
    public Mono<TubeDownloadDto.Job> report(@Valid @RequestBody TubeDownloadDto.ReportRequest body) {
        return service.report(body.jobId(), body.workerId(), body.result(),
                        body.bytes(), body.contentPath(), body.error())
                .map(TubeDownloadDto.Job::of);
    }
}
