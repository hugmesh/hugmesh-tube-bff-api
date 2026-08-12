package net.hugmesh.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.tubebff.testsupport.TestIssuer;

import java.util.List;

/**
 * Hardened HTTP-RESPONSE-HEADER security slice — proves the reactive
 * {@code .headers(...)} block added to {@link SecurityConfig#filterChain} emits the
 * BFF defence-in-depth header set on a real response, on the REAL production filter
 * chain via {@link SecuritySliceSupport}.
 *
 * <p>This is a pure-JSON BFF that always sits BEHIND the TLS-terminating
 * hugmesh-gateway, so the asserted set is the API-defensive minimum (OWASP
 * secure-headers / NIST 800-228 / ASVS V14.4), NOT the gateway front-door set:
 * <ul>
 *   <li><b>ADDED</b> — {@code Content-Security-Policy: default-src 'none';
 *       frame-ancestors 'none'} (no-document API CSP).</li>
 *   <li><b>KEPT</b> (Spring reactive secure defaults, deliberately not disabled) —
 *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY},
 *       {@code Cache-Control} no-store, {@code Referrer-Policy}.</li>
 *   <li><b>OMITTED</b> (correct-by-design for a plaintext intra-mesh JSON BFF) —
 *       {@code Strict-Transport-Security} (lives only at the gateway TLS edge),
 *       {@code Permissions-Policy} (no browsing context to constrain).</li>
 * </ul>
 *
 * <p>The header block is additive: it does NOT change the authz floor, so this slice
 * also asserts an anonymous request to a gated path still 401s — proving the
 * deny-by-default posture is preserved alongside the new headers.
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    /** A reachable authenticated endpoint (the {@code /bff/tube/**} floor) + the
     *  public probe — both 200 so the headers ride a real response body. */
    @RestController
    static class HeaderController {
        @GetMapping("/bff/tube/view/me") Mono<String> floor() { return Mono.just("ok"); }
        @GetMapping("/actuator/health")  Mono<String> health() { return Mono.just("UP"); }
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
        client = sliceClient(registry, provider(resolver), new HeaderController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        other.close();
    }

    // ---- hardened headers present on an AUTHENTICATED 200 response -------------------

    @Test
    void hardenedHeaders_presentOnAuthenticatedResponse() {
        String token = issuer.mint("u", List.of("tube"));
        client.get().uri("/bff/tube/view/me")
                .headers(hh -> hh.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                // ADDED: the no-document API CSP.
                .expectHeader().valueEquals(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                // KEPT: Spring reactive secure defaults (NOT disabled by the header block).
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().exists("Cache-Control")
                .expectHeader().exists("Referrer-Policy")
                // OMITTED-BY-DESIGN: HSTS belongs only at the gateway TLS edge, never on
                // a plaintext intra-mesh JSON BFF hop.
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }

    // ---- the same hardened CSP also rides the public probe response -----------------

    @Test
    void hardenedCsp_presentOnPublicProbe() {
        client.get().uri("/actuator/health")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
    }

    // ---- header block is ADDITIVE: the deny-by-default floor still 401s anon ---------

    @Test
    void anonymous_stillUnauthorized_onGatedPath() {
        client.get().uri("/bff/tube/view/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
