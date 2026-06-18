package systems.snapdragon.tubebff.media;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;
import systems.snapdragon.tubebff.config.SecurityConfig;
import systems.snapdragon.tubebff.web.ApiException;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * Reactive @WebFluxTest for {@link TubeMediaController} — exercises the
 * security gating, the DEFAULT-DENY use gate, path validation, and owner two-wall.
 *
 * <ul>
 *   <li>DEFAULT-DENY use gate: a principal the {@link TubeAccessGuard} denies (no grant /
 *       banned) is 403'd from {@code /sign} — BEFORE any path or owner handling — even for
 *       their OWN valid path.</li>
 *   <li>Happy path: a ROLE_TUBE principal the gate ALLOWS, with a valid matching path →
 *       200 + signed URL.</li>
 *   <li>Wrong owner in path → 403.</li>
 *   <li>Wrong domain in path → 403.</li>
 *   <li>Path with {@code ..} → 400 (path traversal).</li>
 *   <li>Path without domain/subject prefix → 400 (pattern mismatch).</li>
 *   <li>Unauthenticated → 401.</li>
 * </ul>
 *
 * <p>The {@link TubeMediaTokenService} is loaded as a real bean with a test key
 * injected via a {@link TubeMediaTestConfig} inner configuration, so the signing
 * path is exercised end-to-end without mocking. The {@link TubeAccessGuard} is a
 * {@code @MockitoBean} so each test pins the use decision (allow vs deny) explicitly;
 * the {@code @BeforeEach} defaults it to ALLOW so the path/owner-wall tests still reach
 * the body, and the dedicated default-deny test pins it to DENY.
 */
@WebFluxTest(controllers = TubeMediaController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class, TubeMediaControllerTest.TubeMediaTestConfig.class})
class TubeMediaControllerTest {

    /**
     * Provides a real {@link TubeMediaTokenService} backed by a fixed test key so the
     * signing logic runs for real in the slice test (no mock needed — we verify the
     * shape of the response, not the HMAC value).
     */
    @org.springframework.boot.test.context.TestConfiguration
    static class TubeMediaTestConfig {
        @org.springframework.context.annotation.Bean
        TubeMediaTokenService tubeMediaTokenService() {
            String key = Base64.getEncoder()
                    .encodeToString("01234567890123456789012345678901".getBytes());
            return new TubeMediaTokenService(key);
        }
    }

    @Autowired WebTestClient web;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** The DEFAULT-DENY use overlay gate — mocked so each test pins the use decision.
     *  Defaulted to ALLOW in {@link #allowUseByDefault()}; the default-deny test re-pins
     *  it to DENY. */
    @MockitoBean TubeAccessGuard useGate;

    @BeforeEach
    void allowUseByDefault() {
        // Most tests assert the path-safety / owner-two-wall behaviour AFTER the use gate,
        // so default the gate to ALLOW (an empty Mono = "use permitted").
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
    }

    // ── helper: a ROLE_TUBE user whose JWT subject is "alice" and whose issuer maps
    //    to DOMAIN_default (the single-issuer fallback DomainRegistry always resolves).
    private WebTestClient asTubeUser(String subject) {
        return web.mutateWith(mockJwt()
                .jwt(b -> b.subject(subject))
                .authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_TUBE"),
                        // The CasdoorAuthorities converter stamps exactly one DOMAIN_<x>;
                        // in the slice test we stamp it directly so Roles.domainOf(authorities)
                        // resolves "default".
                        new SimpleGrantedAuthority("DOMAIN_default")));
    }

    // ── DEFAULT-DENY use gate (fail-first: fails against the un-gated controller) ──

    @Test
    void sign_forbidden_whenUseGateDenies_evenForOwnValidPath() {
        // A ROLE_TUBE principal who is banned / has no active grant: the use gate errors 403.
        // The path is the caller's OWN valid /default/alice/... path — so the ONLY thing that
        // can deny it is the use gate. Against the unfixed controller (no useGate.assertCanUse)
        // this returned 200; with the fix it must be 403 BEFORE any signing happens.
        when(useGate.assertCanUse(any())).thenReturn(
                Mono.error(ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTubeUser("alice")
                .get().uri("/bff/tube/media/sign?path=/default/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    @Test
    void sign_forbidden_whenUseGateBans_evenForOwnValidPath() {
        // The ban arm of the overlay (ban > grant) — also 403 from /sign for the caller's
        // own valid path. Distinct from the no-grant arm above so a mutation that only
        // honours one of the two guard error messages still fails a test.
        when(useGate.assertCanUse(any())).thenReturn(
                Mono.error(ApiException.forbidden("tube use is banned for this principal in this brand")));
        asTubeUser("alice")
                .get().uri("/bff/tube/media/sign?path=/default/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void sign_happyPath_returns200WithSignedUrl() {
        asTubeUser("alice")
                .get().uri("/bff/tube/media/sign?path=/default/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.url").value((String url) -> {
                    org.assertj.core.api.Assertions.assertThat(url)
                            .startsWith("/tube/content/default/alice/videos/vid.mp4?")
                            .contains("sig=")
                            .contains("exp=")
                            .contains("sub=alice")
                            .contains("domain=default");
                })
                .jsonPath("$.expiresAt").exists();
    }

    // ── owner two-wall rejections ─────────────────────────────────────────────

    @Test
    void sign_wrongSubjectInPath_returns403() {
        // alice tries to sign a URL for eve's content
        asTubeUser("alice")
                .get().uri("/bff/tube/media/sign?path=/default/eve/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    @Test
    void sign_wrongDomainInPath_returns403() {
        // alice (in domain "default") tries to sign a URL for domain "other-brand"
        asTubeUser("alice")
                .get().uri("/bff/tube/media/sign?path=/other-brand/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    // ── path validation rejections ────────────────────────────────────────────

    @Test
    void sign_pathWithDotDot_returns400() {
        asTubeUser("alice")
                .get().uri(uriBuilder -> uriBuilder
                        .path("/bff/tube/media/sign")
                        .queryParam("path", "/default/alice/../../../etc/passwd")
                        .build())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").exists();
    }

    @Test
    void sign_pathWithDoubleSlash_returns400() {
        asTubeUser("alice")
                .get().uri(uriBuilder -> uriBuilder
                        .path("/bff/tube/media/sign")
                        .queryParam("path", "/default/alice//videos/vid.mp4")
                        .build())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").exists();
    }

    @Test
    void sign_pathWithoutDomainSubjectPrefix_returns400() {
        // Only one segment — no domain/subject prefix structure
        asTubeUser("alice")
                .get().uri(uriBuilder -> uriBuilder
                        .path("/bff/tube/media/sign")
                        .queryParam("path", "/vid.mp4")
                        .build())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").exists();
    }

    @Test
    void sign_pathWithSpecialChars_returns400() {
        asTubeUser("alice")
                .get().uri(uriBuilder -> uriBuilder
                        .path("/bff/tube/media/sign")
                        .queryParam("path", "/default/alice/videos/<script>")
                        .build())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").exists();
    }

    // ── unauthenticated ───────────────────────────────────────────────────────

    @Test
    void sign_unauthenticated_returns401() {
        web.get().uri("/bff/tube/media/sign?path=/default/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
