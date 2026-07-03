package systems.snapdragon.tubebff.google;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;

/**
 * The subscribed-channels surface — {@code /bff/tube/subscriptions/**}. Lists the owner's
 * mirrored YouTube subscriptions and triggers a sync from Google.
 *
 * <p><b>Two gates on every method</b> (same stance as {@link GoogleConnectController}):
 * {@link TubeAccessGuard#assertCanUse} (the DEFAULT-DENY use overlay) first, then
 * OWNER-SCOPE via the server-derived {@link PersonalOwner} {@code (subject, domain)} —
 * a user only ever lists/syncs THEIR OWN subscriptions in THEIR brand (fail-closed; no
 * cross-brand bypass). The sync never returns the refresh token or any secret.
 */
@Tag(name = "Tube Subscriptions", description = "List + sync a user's subscribed YouTube "
        + "channels. Gated by the tube_access use overlay (TubeAccessGuard) + owner-scope "
        + "(server-derived subject+brand, fail-closed). A failed refresh sets "
        + "reauth_required and STOPS the sync.")
@RestController
@RequestMapping("/bff/tube/subscriptions")
public class TubeSubscriptionsController {

    /** The authenticated floor, matching the sibling {@code TubeDownloadController} /
     *  {@code TubeMediaController} defence-in-depth pattern. The exact use decision (an
     *  active grant AND NOT an active ban, SUPERADMIN exempt) is enforced programmatically
     *  by {@link TubeAccessGuard#assertCanUse} in each handler — a static SpEL cannot
     *  consult the DB for a per-principal grant/ban. */
    private static final String AUTHENTICATED = "isAuthenticated()";

    private final TubeAccessGuard useGate;
    private final SubscriptionsSyncService sync;

    public TubeSubscriptionsController(TubeAccessGuard useGate, SubscriptionsSyncService sync) {
        this.useGate = useGate;
        this.sync = sync;
    }

    @Operation(operationId = "listSubscriptions",
            summary = "List the current user's stored subscribed channels (owner-scoped; "
            + "no network call). Use-gated.")
    @PreAuthorize(AUTHENTICATED)
    @GetMapping
    public Mono<TubeGoogleDto.SubscriptionList> list(Authentication auth) {
        return useGate.assertCanUse(auth)
                .thenMany(Flux.defer(() -> sync.list(auth)))   // gated: not invoked until use is allowed
                .map(TubeGoogleDto.Subscription::of)
                .collectList()
                .map(TubeGoogleDto.SubscriptionList::new);
    }

    @Operation(operationId = "syncSubscriptions",
            summary = "Sync the current user's subscriptions from Google (refresh -> page "
            + "subscriptions.list?mine=true -> idempotent UPSERT). A failed refresh marks "
            + "reauth_required and STOPS. Use-gated + owner-scoped.")
    @PreAuthorize(AUTHENTICATED)
    @PostMapping("/sync")
    public Mono<ResponseEntity<TubeGoogleDto.SyncResult>> sync(Authentication auth) {
        return useGate.assertCanUse(auth)
                .then(Mono.defer(() -> sync.sync(auth)))   // gated
                .map(n -> ResponseEntity.ok(new TubeGoogleDto.SyncResult(n)));
    }
}
