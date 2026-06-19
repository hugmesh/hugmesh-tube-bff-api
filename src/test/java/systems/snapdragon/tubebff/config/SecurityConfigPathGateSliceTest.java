package systems.snapdragon.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.config.TenancyResolvers;
import systems.snapdragon.commons.config.TenancyResourceServerConfig;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.tubebff.testsupport.TestIssuer;

import java.util.List;

/**
 * COARSE PATH-GATE security slice — proves this repo's {@code authorizeExchange}
 * route/role table ({@link SecurityConfig#commonRoutes}) is enforced as written, on
 * the REAL production filter chain via {@link SecuritySliceSupport}.
 *
 * <p>The route/role table is byte-identical regardless of which OAuth2 resource-server
 * path is wired (single-issuer {@code o.jwt(...)} vs the multi-issuer resolver). This
 * slice drives the chain through the multi-issuer resolver (the same path
 * {@link MultiIssuerSecuritySliceTest} uses) because it builds its own real
 * {@link org.springframework.security.oauth2.jwt.ReactiveJwtDecoder} from the in-process
 * {@link TestIssuer}'s JWKS — no Spring Boot autoconfig (which is what supplies the
 * decoder for the single-issuer {@code o.jwt(...)} path in production) is present in a
 * slice. Tokens are minted by ONE trusted issuer; the second trusted issuer exists only
 * so {@link DomainRegistry#isMultiIssuer()} engages the resolver. The shared Casdoor
 * converter maps {@code roles} → {@code ROLE_<UPPER>} on whichever path validates.
 *
 * <table>
 *   <caption>The route/role table under test (most-specific first)</caption>
 *   <tr><th>Path prefix</th><th>Gate</th></tr>
 *   <tr><td>{@code /actuator/health}</td><td>permitAll (public probe)</td></tr>
 *   <tr><td>{@code /bff/tube/superadmin/**}</td><td>hasRole(SUPERADMIN)</td></tr>
 *   <tr><td>{@code /bff/tube/internal/**}</td><td>hasRole(TUBE_WORKER) — NO human edge</td></tr>
 *   <tr><td>{@code /bff/tube/admin/**}</td><td>hasAnyRole(ADMIN, SUPERADMIN)</td></tr>
 *   <tr><td>{@code /bff/tube/google-connect/**}</td><td>hasRole(TUBE)</td></tr>
 *   <tr><td>{@code /bff/tube/subscriptions/**}</td><td>hasRole(TUBE)</td></tr>
 *   <tr><td>{@code /bff/tube/**}</td><td>authenticated (floor)</td></tr>
 *   <tr><td>anything else</td><td>authenticated</td></tr>
 * </table>
 *
 * <p>Anonymous (no bearer) is 401 on every gated path. ROLE checks are
 * fail-closed: a role NOT carried by the token is denied (403). Note the converter
 * floors every authenticated principal to {@code ROLE_USER}, so the role-hierarchy
 * edges ({@code SUPERADMIN > ADMIN}) let a SUPERADMIN token reach the ADMIN surface.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    /** Echo controllers, one per gated prefix — each returns 200 so a reachable path
     *  proves the gate let the principal through, while a 401/403 proves the gate. */
    @RestController
    static class GatedController {
        @GetMapping("/bff/tube/superadmin/all")     Mono<String> superadmin() { return Mono.just("ok"); }
        @GetMapping("/bff/tube/internal/claim")      Mono<String> internal()   { return Mono.just("ok"); }
        @GetMapping("/bff/tube/admin/grant")         Mono<String> admin()      { return Mono.just("ok"); }
        @GetMapping("/bff/tube/google-connect/start")Mono<String> connect()    { return Mono.just("ok"); }
        @GetMapping("/bff/tube/subscriptions/list")  Mono<String> subs()       { return Mono.just("ok"); }
        @GetMapping("/bff/tube/view/me")             Mono<String> floor()      { return Mono.just("ok"); }
        @GetMapping("/actuator/health")              Mono<String> health()     { return Mono.just("UP"); }
    }

    private TestIssuer issuer;       // mints every token in this slice
    private TestIssuer other;        // second trusted issuer -> isMultiIssuer() true
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

    private WebTestClient.ResponseSpec get(String uri, String... roles) {
        String token = issuer.mint("u", List.of(roles));
        return client.get().uri(uri)
                .headers(h -> h.setBearerAuth(token))
                .exchange();
    }

    private WebTestClient.ResponseSpec getAnon(String uri) {
        return client.get().uri(uri).exchange();
    }

    // ---- public probe ---------------------------------------------------------------

    @Test
    void actuatorHealth_isPublic() {
        getAnon("/actuator/health").expectStatus().isOk();
    }

    // ---- anonymous is 401 everywhere gated ------------------------------------------

    @Test
    void anonymous_is401_onEveryGatedPath() {
        getAnon("/bff/tube/superadmin/all").expectStatus().isUnauthorized();
        getAnon("/bff/tube/internal/claim").expectStatus().isUnauthorized();
        getAnon("/bff/tube/admin/grant").expectStatus().isUnauthorized();
        getAnon("/bff/tube/google-connect/start").expectStatus().isUnauthorized();
        getAnon("/bff/tube/subscriptions/list").expectStatus().isUnauthorized();
        getAnon("/bff/tube/view/me").expectStatus().isUnauthorized();
    }

    // ---- /bff/tube/superadmin/** -> SUPERADMIN only ---------------------------------

    @Test
    void superadminSurface_allowsSuperadmin_deniesAdminAndUser() {
        get("/bff/tube/superadmin/all", "superadmin").expectStatus().isOk();
        get("/bff/tube/superadmin/all", "admin").expectStatus().isForbidden();
        get("/bff/tube/superadmin/all", "tube").expectStatus().isForbidden();
    }

    // ---- /bff/tube/internal/** -> TUBE_WORKER only (NO human role edge) --------------

    @Test
    void internalWorkerSurface_allowsWorker_deniesSuperadminAndAdmin() {
        get("/bff/tube/internal/claim", "tube_worker").expectStatus().isOk();
        // The worker prefix is deliberately OUTSIDE the human role hierarchy: even
        // SUPERADMIN must NOT be able to claim/complete a download job.
        get("/bff/tube/internal/claim", "superadmin").expectStatus().isForbidden();
        get("/bff/tube/internal/claim", "admin").expectStatus().isForbidden();
    }

    // ---- /bff/tube/admin/** -> ADMIN or SUPERADMIN ----------------------------------

    @Test
    void adminGovernSurface_allowsAdminAndSuperadmin_deniesPlainTube() {
        get("/bff/tube/admin/grant", "admin").expectStatus().isOk();
        // SUPERADMIN reaches it via the role-hierarchy edge SUPERADMIN > ADMIN.
        get("/bff/tube/admin/grant", "superadmin").expectStatus().isOk();
        get("/bff/tube/admin/grant", "tube").expectStatus().isForbidden();
    }

    // ---- /bff/tube/google-connect/** + /subscriptions/** -> ROLE_TUBE ---------------

    @Test
    void connectAndSubscriptions_requireRoleTube() {
        get("/bff/tube/google-connect/start", "tube").expectStatus().isOk();
        get("/bff/tube/subscriptions/list", "tube").expectStatus().isOk();
        // A plain user (only the ROLE_USER floor) lacks ROLE_TUBE -> 403.
        get("/bff/tube/google-connect/start", "somethingelse").expectStatus().isForbidden();
        get("/bff/tube/subscriptions/list", "somethingelse").expectStatus().isForbidden();
    }

    // ---- /bff/tube/** floor -> authenticated ----------------------------------------

    @Test
    void floor_allowsAnyAuthenticatedPrincipal() {
        // Even a token carrying no roles is floored to ROLE_USER => authenticated.
        get("/bff/tube/view/me").expectStatus().isOk();
    }
}
