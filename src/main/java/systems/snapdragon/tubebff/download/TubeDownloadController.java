package systems.snapdragon.tubebff.download;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;

/**
 * The USER-facing download work-queue surface — list the caller's own jobs + enqueue jobs
 * from their subscriptions. Mounted under {@code /bff/tube/downloads} (the
 * {@code .authenticated()} floor in {@link systems.snapdragon.tubebff.config.SecurityConfig}).
 *
 * <p><b>Default-deny use is enforced FIRST.</b> Every action calls
 * {@link TubeAccessGuard#assertCanUse} before touching the queue, so a principal without an
 * active {@code tube_access} use grant (or under an active ban) is 403'd — the bare
 * {@code ROLE_TUBE} floor does NOT confer queue access (SUPERADMIN is the only exemption,
 * inside the guard).
 *
 * <p><b>Owner + brand are server-derived.</b> {@link DownloadJobService} derives the owner
 * subject + brand from the validated JWT, so a user can only ever list/enqueue THEIR OWN
 * jobs in THEIR OWN brand — user A can never reach user B's queue, and no request field can
 * forge a cross-user/cross-brand scope.
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

    @Operation(summary = "List the calling user's OWN download jobs (owner + brand "
            + "server-derived). Default-deny use enforced first.")
    @PreAuthorize(AUTHENTICATED)
    @GetMapping
    public Mono<TubeDownloadDto.JobList> list(Authentication auth) {
        return useGate.assertCanUse(auth)
                .thenMany(service.listForOwner(auth))
                .map(TubeDownloadDto.Job::of)
                .collectList()
                .map(TubeDownloadDto.JobList::new);
    }

    @Operation(summary = "Enqueue download jobs from the calling user's subscriptions "
            + "(deduped; pause-on-full marks new work skipped when the storage budget is "
            + "full). Owner + brand server-derived. Default-deny use enforced first.")
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
