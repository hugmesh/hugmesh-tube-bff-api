package net.hugmesh.tubebff.download;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.tubebff.access.TubeAccessGuard;
import net.hugmesh.tubebff.config.SecurityConfig;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.tubebff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The USER download surface gating + the DEFAULT-DENY use gate (reactive @WebFluxTest):
 *
 * <ul>
 *   <li>list/enqueue require an authenticated principal AND pass the {@link TubeAccessGuard}
 *       use gate first — an authenticated user WITHOUT a grant is 403'd (the bare ROLE_TUBE
 *       floor does not confer queue access).</li>
 *   <li>with the use gate allowing, list returns the owner's jobs (owner server-derived in
 *       the service — the controller never reads a subject from the request).</li>
 *   <li>an unauthenticated request is 401.</li>
 * </ul>
 */
@WebFluxTest(controllers = TubeDownloadController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class TubeDownloadControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DownloadJobService service;
    @MockitoBean TubeAccessGuard useGate;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asTubeUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private static DownloadJob job(String state) {
        return new DownloadJob("id-1", "default", "alice", "chan", "vid", "Title",
                state, null, null, 0, null, null, null, Instant.now(), Instant.now());
    }

    // ── DEFAULT-DENY use gate ─────────────────────────────────────────────────
    @Test
    void list_forbidden_whenUseGateDenies() {
        // The use gate (programmatic default-deny) errors 403 for a principal without a grant.
        when(useGate.assertCanUse(any()))
                .thenReturn(Mono.error(ApiException.forbidden("tube use requires an active grant")));
        asTubeUser().get().uri("/bff/tube/downloads")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void enqueue_forbidden_whenUseGateDenies() {
        when(useGate.assertCanUse(any()))
                .thenReturn(Mono.error(ApiException.forbidden("tube use is banned for this principal")));
        asTubeUser().post().uri("/bff/tube/downloads")
                .exchange().expectStatus().isForbidden();
    }

    // ── allowed (use gate passes) ─────────────────────────────────────────────
    @Test
    void list_allowed_whenUseGatePasses_returnsOwnerJobs() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(service.listForOwner(any())).thenReturn(Flux.just(job(DownloadJob.STATE_QUEUED)));
        asTubeUser().get().uri("/bff/tube/downloads")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.jobs[0].state").isEqualTo("queued")
                .jsonPath("$.jobs[0].userSubject").isEqualTo("alice");
    }

    @Test
    void enqueue_allowed_whenUseGatePasses() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(service.enqueueFromSubscriptions(any())).thenReturn(Flux.just(job(DownloadJob.STATE_QUEUED)));
        asTubeUser().post().uri("/bff/tube/downloads")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.jobs[0].state").isEqualTo("queued");
    }

    // ── unauthenticated ───────────────────────────────────────────────────────
    @Test
    void list_unauthenticated_is401() {
        web.get().uri("/bff/tube/downloads")
                .exchange().expectStatus().isUnauthorized();
    }
}
