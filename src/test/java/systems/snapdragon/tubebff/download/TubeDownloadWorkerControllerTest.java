package systems.snapdragon.tubebff.download;

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
import systems.snapdragon.tubebff.config.SecurityConfig;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * THE SECURITY-CRITICAL worker-seam gate (reactive @WebFluxTest): the internal
 * claim/report endpoints are reachable ONLY by a {@code ROLE_TUBE_WORKER} service
 * principal — NOT by a plain {@code ROLE_TUBE} user, nor by any human role
 * (USER/MOD/ADMIN/SUPERADMIN). This is the boundary that keeps a human from claiming or
 * completing another user's download job. Both the path gate (SecurityConfig
 * {@code /bff/tube/internal/**}) and the method @PreAuthorize enforce it.
 */
@WebFluxTest(controllers = TubeDownloadWorkerController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class TubeDownloadWorkerControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DownloadJobService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static DownloadJob job() {
        return new DownloadJob("id-1", "default", "alice", "chan", "vid", "Title",
                DownloadJob.STATE_CLAIMED, "worker-A", Instant.now(), 1, null, null, null,
                Instant.now(), Instant.now());
    }

    private WebTestClient asWorker() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_TUBE_WORKER")));
    }

    private WebTestClient asTubeUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private static final String CLAIM_BODY = "{\"workerId\":\"worker-A\",\"limit\":5}";
    private static final String REPORT_BODY =
            "{\"jobId\":\"id-1\",\"workerId\":\"worker-A\",\"result\":\"done\",\"bytes\":10}";

    // ── ALLOWED for the worker service principal ──────────────────────────────
    @Test
    void claim_allowedForWorkerPrincipal() {
        when(service.claim(eq("worker-A"), anyInt())).thenReturn(Flux.just(job()));
        asWorker().post().uri("/bff/tube/internal/download-jobs/claim")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CLAIM_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.jobs[0].claimedBy").isEqualTo("worker-A");
    }

    @Test
    void report_allowedForWorkerPrincipal() {
        when(service.report(eq("id-1"), eq("worker-A"), any(), anyLong(), any(), any()))
                .thenReturn(Mono.just(job()));
        asWorker().post().uri("/bff/tube/internal/download-jobs/report")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REPORT_BODY)
                .exchange().expectStatus().isOk();
    }

    // ── DENIED for a plain ROLE_TUBE user (the load-bearing denial) ───────────
    @Test
    void claim_forbiddenForPlainTubeUser() {
        asTubeUser().post().uri("/bff/tube/internal/download-jobs/claim")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CLAIM_BODY)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void report_forbiddenForPlainTubeUser() {
        asTubeUser().post().uri("/bff/tube/internal/download-jobs/report")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REPORT_BODY)
                .exchange().expectStatus().isForbidden();
    }

    /** Even SUPERADMIN is denied the worker seam — the worker role is deliberately OUTSIDE
     *  the human role hierarchy (a human must never claim/complete another user's job). */
    @Test
    void claim_forbiddenForSuperadmin_workerRoleIsOutsideHumanHierarchy() {
        asSuperadmin().post().uri("/bff/tube/internal/download-jobs/claim")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CLAIM_BODY)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void claim_unauthenticated_is401() {
        web.post().uri("/bff/tube/internal/download-jobs/claim")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CLAIM_BODY)
                .exchange().expectStatus().isUnauthorized();
    }
}
