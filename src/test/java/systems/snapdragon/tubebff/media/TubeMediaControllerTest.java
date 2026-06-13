package systems.snapdragon.tubebff.media;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.tubebff.config.SecurityConfig;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.util.Base64;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * Reactive @WebFluxTest for {@link TubeMediaController} — exercises the
 * security gating, path validation, and owner two-wall.
 *
 * <ul>
 *   <li>Happy path: a ROLE_TUBE principal with a valid matching path → 200 + signed URL.</li>
 *   <li>Wrong owner in path → 403.</li>
 *   <li>Wrong domain in path → 403.</li>
 *   <li>Path with {@code ..} → 400 (path traversal).</li>
 *   <li>Path without domain/subject prefix → 400 (pattern mismatch).</li>
 *   <li>Unauthenticated → 401.</li>
 * </ul>
 *
 * <p>The {@link TubeMediaTokenService} is loaded as a real bean with a test key
 * injected via a {@link TubeMediaTestConfig} inner configuration, so the signing
 * path is exercised end-to-end without mocking.
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
