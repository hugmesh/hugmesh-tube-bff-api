package systems.hugmesh.tubebff.config;


import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.config.TenancyResolvers;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.tubebff.testsupport.TestIssuer;

import java.util.List;

/**
 * The wave-2c BODY-of-DENY gap closer for the ADMIN / SUPERADMIN path-gate
 * ({@link SecurityConfig#commonRoutes}) — driven on the REAL filter chain with real
 * RS256 tokens minted by the in-process {@link TestIssuer}.
 *
 * <p>The existing {@code TubeStorageBudgetControllerTest} / {@code TubeAccessControllerTest}
 * assert the DENY cases with STATUS ONLY ({@code .expectStatus().isForbidden()}). This
 * slice adds the BODY assertion the wave-2c mission asks for — but the ACCURATE one: a
 * filter-chain path-gate denial (and a no-bearer 401) is emitted by the resource server /
 * authorization filter BEFORE any controller runs, and production wires no custom
 * {@code ServerAuthenticationEntryPoint} / {@code ServerAccessDeniedHandler}, so the 401/403
 * carries NO {@code {"error":...}} body. Asserting the body is EMPTY is therefore the
 * mutation-resistant truth: it proves the gate denies before the controller AND that the
 * BFF leaks no JSON on a gate denial. (The {@code $.error} body is reserved for
 * controller-body {@code ApiException}s — exercised in {@code TubeMediaSecuritySliceTest}
 * and the existing media controller test.)
 *
 * <p>These DENY assertions are mutation-resistant against the route table: a
 * {@code somethingelse}/{@code tube} token reaches the gated path and is 403'd ONLY because
 * the {@code hasAnyRole('ADMIN','SUPERADMIN')} gate denies it — drop that gate (e.g.
 * {@code .authenticated()}) and the request would reach the 200 echo controller and the
 * test would FAIL.
 */
class TubeAdminPathGateBodySliceTest extends SecuritySliceSupport {

    /** Echo controllers mounted on the exact gated prefixes — a reachable 200 proves the
     *  gate let the principal through; a 401/403 proves the gate denied. */
    @RestController
    static class GatedController {
        @PostMapping("/bff/tube/admin/storage-budget") Mono<String> budget() { return Mono.just("ok"); }
        @GetMapping("/bff/tube/admin/access/grant")      Mono<String> grant()  { return Mono.just("ok"); }
        @GetMapping("/bff/tube/superadmin/access")       Mono<String> manage() { return Mono.just("ok"); }
    }

    private TestIssuer issuer;   // mints every token here
    private TestIssuer other;    // second trusted issuer → isMultiIssuer() engages the resolver
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        other = new TestIssuer();
        DomainRegistry registry = new DomainRegistry(
                issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + other.issuerUri() + "=brandy");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(
                        new TenancyResourceServerConfig(registry, "", "", false, 600_000L));
        client = sliceClient(registry, provider(resolver), new GatedController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        other.close();
    }

    private WebTestClient.ResponseSpec postBudgetAs(String... roles) {
        String token = issuer.mint("u", List.of(roles));
        return client.post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .headers(h -> h.setBearerAuth(token))
                .exchange();
    }

    // ── budget_plainTubeUser_is403 (path-gate DENY + accurate empty body) ──────

    @Test
    void budget_plainTubeUser_is403_noErrorBodyLeaked() {
        // A plain ROLE_TUBE user (floored to ROLE_USER + ROLE_TUBE) lacks ADMIN/SUPERADMIN
        // → the /bff/tube/admin/** path-gate denies it before the controller. 403, empty
        // body. Mutation-resistant: loosen the gate and this 403 becomes the 200 echo.
        postBudgetAs("tube")
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void budget_allowedForAdmin_reachesController() {
        // The ALLOW side: an ADMIN token clears the gate and hits the echo controller.
        postBudgetAs("admin").expectStatus().isOk();
    }

    @Test
    void budget_noBearer_is401_noErrorBodyLeaked() {
        client.post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    // ── TubeAccessController admin/superadmin path-gate (DENY + accurate body) ──

    @Test
    void accessGrant_plainTubeUser_is403_noErrorBodyLeaked() {
        // The TUBE_GOVERN seam is /bff/tube/admin/access/** → ADMIN|SUPERADMIN. A plain
        // ROLE_TUBE (or even ROLE_MOD+ROLE_TUBE) holder is denied at the path-gate.
        String token = issuer.mint("u", List.of("mod", "tube"));
        client.get().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void manageAll_plainAdmin_is403_noErrorBodyLeaked() {
        // The TUBE_MANAGE seam is /bff/tube/superadmin/** → SUPERADMIN only. A plain ADMIN
        // is denied (no ADMIN→SUPERADMIN hierarchy edge).
        String token = issuer.mint("u", List.of("admin"));
        client.get().uri("/bff/tube/superadmin/access")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void manageAll_superadmin_reachesController() {
        // ALLOW side: SUPERADMIN clears the superadmin gate.
        String token = issuer.mint("u", List.of("superadmin"));
        client.get().uri("/bff/tube/superadmin/access")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk();
    }
}
