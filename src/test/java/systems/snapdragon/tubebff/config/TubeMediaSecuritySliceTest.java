package systems.snapdragon.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.snapdragon.tubebff.media.TubeMediaController;
import systems.snapdragon.tubebff.media.TubeMediaTokenService;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.testsupport.TestIssuer;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.util.Base64;
import java.util.List;

/**
 * MEDIA-SIGNING security slice — the wave-2c gap closer for {@link TubeMediaController}.
 *
 * <p>Unlike the existing {@code TubeMediaControllerTest} (a {@code @WebFluxTest} that
 * stamps a {@code DOMAIN_default} authority by hand via {@code mockJwt()}), this slice
 * drives the REAL {@link SecurityConfig#filterChain} + the REAL multi-issuer per-brand
 * resolver ({@link TenancyResourceServerConfig}) on real RS256 tokens minted by the
 * in-process {@link TestIssuer}s — so the {@code DOMAIN_<x>} authority the controller's
 * wall-2 domain check reads is the cryptographically-derived one stamped by
 * {@code CasdoorAuthorities} at validation time, NOT a hand-placed test authority. The
 * brand is bound to the token's {@code iss}; a brand-Y token can therefore NEVER acquire
 * brand-X's {@code DOMAIN_brandx} authority, which is exactly what makes the cross-brand
 * 403 a real end-to-end isolation proof rather than a re-derivation of the test's own
 * stamp.
 *
 * <p><b>What this slice asserts</b> (all through the production chain):
 * <ul>
 *   <li><b>ALLOW (USER-SITUATIONAL)</b> — a brand-X token signing its OWN
 *       {@code /brandx/<sub>/...} path → 200 with the signed URL bound to that brand.</li>
 *   <li><b>DENY cross-brand (CROSS-USER) — {@code media_brandYToken_signingIntoBrandX_is403}</b>
 *       — a brand-Y token signing a {@code /brandx/...} path → 403 with the
 *       {@code {"error":...}} body. Mutation-resistant: the path domain is read from the
 *       issuer-derived authority, so removing the wall-2 domain check (or letting a
 *       brand-Y token reach brand-X scope) would flip this to 200/2xx and FAIL.</li>
 *   <li><b>DENY cross-subject (CROSS-USER)</b> — a brand-X token signing another
 *       subject's {@code /brandx/eve/...} path → 403 + {@code $.error}.</li>
 *   <li><b>DENY no-bearer — {@code media_noBearer_is401}</b> — 401 from the resource
 *       server entry point. The body assertion here is the ACCURATE one: the filter-chain
 *       401 carries NO {@code $.error} body (production declares no custom
 *       {@code ServerAuthenticationEntryPoint}), so we assert the body is empty — proving
 *       the gate denies BEFORE the controller and leaks no JSON.</li>
 *   <li><b>DENY path-traversal (400)</b> — a {@code ..} path → 400 + {@code $.error}
 *       (the controller's allowlist pattern rejects before any signing).</li>
 * </ul>
 */
class TubeMediaSecuritySliceTest extends SecuritySliceSupport {

    /** A fixed 32-byte key (base64) so the REAL signer runs — we assert response shape,
     *  not the HMAC value, exactly like the existing media controller test. */
    private static final String MEDIA_KEY =
            Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes());

    private TestIssuer brandX;
    private TestIssuer brandY;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        DomainRegistry registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                new TenancyResourceServerConfig(registry, "", "").tenantAuthManagerResolver();
        // Register ApiExceptionHandler so a controller-body Mono.error(ApiException) renders
        // its mapped status + {"error":...} body (the owner two-wall 403 / path 400) instead
        // of an unhandled raw 500.
        client = sliceClientWithAdvice(registry, provider(resolver),
                new Object[]{new ApiExceptionHandler()},
                new TubeMediaController(new TubeMediaTokenService(MEDIA_KEY)));
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
    }

    private WebTestClient.RequestHeadersSpec<?> signAs(String token, String path) {
        return client.get()
                .uri(b -> b.path("/bff/tube/media/sign").queryParam("path", path).build())
                .headers(h -> h.setBearerAuth(token));
    }

    // ── ALLOW: own brand + own subject → 200 + signed URL ─────────────────────

    @Test
    void media_brandXToken_signingOwnPath_is200() {
        String token = brandX.mint("alice", List.of("tube"));
        signAs(token, "/brandx/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.url").value((String url) ->
                        org.assertj.core.api.Assertions.assertThat(url)
                                .startsWith("/tube/content/brandx/alice/videos/vid.mp4?")
                                .contains("sub=alice")
                                .contains("domain=brandx"))
                .jsonPath("$.expiresAt").exists();
    }

    // ── DENY cross-brand: brand-Y token cannot sign a brand-X path (403 + $.error) ──

    @Test
    void media_brandYToken_signingIntoBrandX_is403() {
        // A correctly-signed brand-Y token whose iss is cryptographically bound to
        // brand-Y. It authenticates (the /bff/tube/media/** floor is .authenticated()),
        // but its DOMAIN_brandy authority can never equal the path's "brandx" domain.
        String token = brandY.mint("alice", List.of("tube"));
        signAs(token, "/brandx/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.error").exists()
                .jsonPath("$.error").isEqualTo("path domain does not match the caller's brand");
    }

    @Test
    void media_brandYToken_cannotSignBrandXEvenLoadedWithPrivilegedRoles() {
        // Even an admin/superadmin brand-Y token stays brand-Y scoped — privilege does
        // not cross the brand line at the data-derived path.
        String token = brandY.mint("alice", List.of("admin", "superadmin", "tube"));
        signAs(token, "/brandx/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    // ── DENY cross-subject: brand-X token cannot sign another subject's path ───

    @Test
    void media_brandXToken_signingOtherSubject_is403() {
        String token = brandX.mint("alice", List.of("tube"));
        signAs(token, "/brandx/eve/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.error").exists()
                .jsonPath("$.error").isEqualTo("path subject does not match the caller's JWT subject");
    }

    // ── DENY no-bearer: 401 from the resource server, NO $.error body ──────────

    @Test
    void media_noBearer_is401() {
        // The resource-server entry point denies before the controller; production wires
        // no custom ServerAuthenticationEntryPoint, so the 401 carries no $.error body.
        // Asserting the EMPTY body is the accurate, mutation-resistant claim (a $.error
        // assertion here would describe a body production never emits).
        client.get()
                .uri(b -> b.path("/bff/tube/media/sign")
                        .queryParam("path", "/brandx/alice/videos/vid.mp4").build())
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    @Test
    void media_garbageBearer_is401() {
        client.get()
                .uri(b -> b.path("/bff/tube/media/sign")
                        .queryParam("path", "/brandx/alice/videos/vid.mp4").build())
                .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    // ── DENY path-traversal: 400 + $.error (controller allowlist) ──────────────

    @Test
    void media_pathTraversal_is400_withError() {
        String token = brandX.mint("alice", List.of("tube"));
        signAs(token, "/brandx/alice/../../../etc/passwd")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").exists();
    }
}
