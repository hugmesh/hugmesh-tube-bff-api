package systems.snapdragon.tubebff.google;

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

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * {@link GoogleConnectController} gating + contract (@WebFluxTest). Proves, per the test
 * standard:
 *
 * <ul>
 *   <li><b>ROLE_TUBE route floor</b>: a principal WITHOUT ROLE_TUBE is 403 by the
 *       SecurityConfig path gate before any handler runs.</li>
 *   <li><b>USE-GATE (default-deny)</b>: a ROLE_TUBE holder whose
 *       {@link TubeAccessGuard#assertCanUse} DENIES (no grant) gets 403 — the bare role
 *       does not confer use; the guard is invoked on EVERY method.</li>
 *   <li><b>USE-GATE ALLOW</b>: with the guard passing, the connect status / authorize URL
 *       return.</li>
 *   <li><b>NO TOKEN LEAK</b>: the status response carries ONLY display-safe fields — never
 *       a refresh token / ciphertext / DEK.</li>
 * </ul>
 *
 * <p>Owner-scope is enforced SERVER-SIDE inside the service ({@link PersonalOwner} derives
 * the subject+brand from the JWT; there is no request field to forge), so at the controller
 * boundary we assert the gate fires + the response is leak-free; the owner/domain isolation
 * is proven end-to-end in the service slice tests.
 */
@WebFluxTest(controllers = GoogleConnectController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class GoogleConnectControllerTest {

    @Autowired WebTestClient web;

    @MockitoBean TubeAccessGuard useGate;
    @MockitoBean GoogleConnectService connect;
    @MockitoBean TubeGoogleLinkRepository links;
    @MockitoBean PersonalOwner owner;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asTube() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private WebTestClient asUserNoTube() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static PersonalOwner.Owner OWNER = new PersonalOwner.Owner("alice", "brandx");

    // ── ROLE_TUBE route floor (SecurityConfig path gate) ──────────────────────
    @Test
    void status_forbiddenWithoutTubeRole() {
        asUserNoTube().get().uri("/bff/tube/google-connect/status")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void authorize_forbiddenWithoutTubeRole() {
        asUserNoTube().get().uri("/bff/tube/google-connect/authorize")
                .exchange().expectStatus().isForbidden();
    }

    // ── USE-GATE default-deny (guard DENIES even a ROLE_TUBE holder) ───────────
    @Test
    void status_useGateDenies_403_evenWithTubeRole() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.error(
                ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTube().get().uri("/bff/tube/google-connect/status")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void authorize_useGateDenies_403() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.error(
                ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTube().get().uri("/bff/tube/google-connect/authorize")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void disconnect_useGateDenies_403() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.error(
                ApiException.forbidden("tube use requires an active grant (default-deny)")));
        asTube().post().uri("/bff/tube/google-connect/disconnect")
                .exchange().expectStatus().isForbidden();
    }

    // ── USE-GATE allow + NO TOKEN LEAK ────────────────────────────────────────
    @Test
    void status_connected_returnsDisplaySafeFieldsOnly_noRefreshToken() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(owner.resolve(any())).thenReturn(OWNER);
        // A link that DOES carry a ciphertext refresh token server-side...
        TubeGoogleLink link = new TubeGoogleLink("id-1", "brandx", "alice", "g-sub",
                "alice@example.com", "CIPHERTEXT-SECRET-BLOB", "v1", "scope",
                Instant.now(), false, null);
        when(links.findLive("brandx", "alice")).thenReturn(Mono.just(link));

        asTube().get().uri("/bff/tube/google-connect/status")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.connected").isEqualTo(true)
                .jsonPath("$.googleEmail").isEqualTo("alice@example.com")
                // ...but NONE of the secret material crosses the boundary.
                .jsonPath("$.refreshToken").doesNotExist()
                .jsonPath("$.refreshTokenCiphertext").doesNotExist()
                .jsonPath("$.dek").doesNotExist()
                .jsonPath("$.dekId").doesNotExist();
    }

    @Test
    void status_notConnected_returnsConnectedFalse() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(owner.resolve(any())).thenReturn(OWNER);
        when(links.findLive("brandx", "alice")).thenReturn(Mono.empty());
        asTube().get().uri("/bff/tube/google-connect/status")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.connected").isEqualTo(false);
    }

    @Test
    void authorize_allow_returnsConsentUrl() {
        when(useGate.assertCanUse(any())).thenReturn(Mono.empty());
        when(connect.authorizeUrl(any())).thenReturn(Mono.just(
                "https://accounts.google.com/o/oauth2/v2/auth?state=signed"));
        asTube().get().uri("/bff/tube/google-connect/authorize")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.authorizeUrl")
                .isEqualTo("https://accounts.google.com/o/oauth2/v2/auth?state=signed");
    }
}
