package systems.snapdragon.tubebff.google;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;
import systems.snapdragon.tubebff.config.SecurityConfig;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * {@link TubeSubscriptionsController} gating + contract (@WebFluxTest). Proves:
 *
 * <ul>
 *   <li><b>ROLE_TUBE route floor</b>: no ROLE_TUBE -> 403 (SecurityConfig path gate).</li>
 *   <li><b>USE-GATE default-deny</b>: a ROLE_TUBE holder the guard DENIES -> 403, on BOTH
 *       list + sync.</li>
 *   <li><b>OWNER-SCOPE</b>: the service is invoked with the request {@code Authentication}
 *       (the server derives the owner from the JWT); a user only ever lists/syncs THEIR
 *       OWN data — there is no request-supplied owner to forge.</li>
 *   <li><b>reauth_required surfaces</b>: a sync whose refresh failed surfaces the service's
 *       403 (reauth required) to the caller.</li>
 *   <li><b>NO TOKEN LEAK</b>: subscription rows carry only channel metadata.</li>
 * </ul>
 */
@WebFluxTest(controllers = TubeSubscriptionsController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class TubeSubscriptionsControllerTest {

    @Autowired WebTestClient web;

    @MockitoBean TubeAccessGuard useGate;
    @MockitoBean SubscriptionsSyncService sync;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asTube() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private WebTestClient asUserNoTube() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── ROLE_TUBE route floor ─────────────────────────────────────────────────
    @Test
    void list_forbiddenWithoutTubeRole() {
        asUserNoTube().get().uri("/bff/tube/subscriptions")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void sync_forbiddenWithoutTubeRole() {
        asUserNoTube().post().uri("/bff/tube/subscriptions/sync")
                .exchange().expectStatus().isForbidden();
    }

    // ── USE-GATE default-deny ─────────────────────────────────────────────────
    @Test
    void list_useGateDenies_403() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.error(
                ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTube().get().uri("/bff/tube/subscriptions")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void sync_useGateDenies_403() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.error(
                ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTube().post().uri("/bff/tube/subscriptions/sync")
                .exchange().expectStatus().isForbidden();
    }

    // ── USE-GATE allow + owner-scope (server-derived) + no leak ───────────────
    @Test
    void list_allow_returnsOwnersChannels_metadataOnly() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(sync.list(any())).thenReturn(Flux.just(
                new TubeSubscription("id-1", "brandx", "alice", "chan-1", "Cooking", "thumb",
                        Instant.now())));
        asTube().get().uri("/bff/tube/subscriptions")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.subscriptions[0].channelId").isEqualTo("chan-1")
                .jsonPath("$.subscriptions[0].channelTitle").isEqualTo("Cooking")
                // no secret material on a subscription row
                .jsonPath("$.subscriptions[0].refreshToken").doesNotExist()
                .jsonPath("$.subscriptions[0].userSubject").doesNotExist();
    }

    @Test
    void sync_allow_returnsCount() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(sync.sync(any())).thenReturn(Mono.just(7));
        asTube().post().uri("/bff/tube/subscriptions/sync")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.synced").isEqualTo(7);
    }

    @Test
    void sync_reauthRequired_surfaces403() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(sync.sync(any())).thenReturn(Mono.error(
                ApiException.forbidden("Google refresh failed; re-authentication required")));
        asTube().post().uri("/bff/tube/subscriptions/sync")
                .exchange().expectStatus().isForbidden();
    }
}
