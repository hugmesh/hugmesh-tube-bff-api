package net.hugmesh.tubebff.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.tubebff.config.SecurityConfig;
import net.hugmesh.tubebff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The use grant/timeout/ban overlay surface gating + contract (reactive @WebFluxTest):
 *
 * <ul>
 *   <li>grant/timeout/ban/restore (under /bff/tube/admin/access/**) — ALLOWED for ADMIN +
 *       SUPERADMIN (TUBE_GOVERN); FORBIDDEN for a MOD+TUBE holder (the admin prefix is
 *       ADMIN end-to-end) and a plain USER.</li>
 *   <li>list-all/history (under /bff/tube/superadmin/access) — ALLOWED for SUPERADMIN only
 *       (TUBE_MANAGE); FORBIDDEN for a plain ADMIN.</li>
 *   <li>contract: grant returns the active use row; timeout validates ttlSeconds &gt; 0;
 *       restore maps an unknown accessType to 400.</li>
 * </ul>
 */
@WebFluxTest(controllers = TubeAccessController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class TubeAccessControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean TubeAccessService access;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asModTube() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private static TubeAccess active(String type, Instant exp) {
        return new TubeAccess("id-1", "default", "bob", type, TubeAccess.STATE_ACTIVE,
                "admin-x", "reason", Instant.now(), exp, null);
    }

    // ── grant/timeout/ban/restore (TUBE_GOVERN) ────────────────────────
    @Test
    void grant_allowedForAdmin_returnsActiveUseRow() {
        when(access.grant(eq("bob"), any(), any())).thenReturn(Mono.just(active(TubeAccess.TYPE_USE, null)));
        asAdmin().post().uri("/bff/tube/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"reason\":\"enable tube\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.accessType").isEqualTo("use")
                .jsonPath("$.state").isEqualTo("active");
    }

    @Test
    void ban_allowedForSuperadmin() {
        when(access.ban(eq("bob"), any(), any())).thenReturn(Mono.just(active(TubeAccess.TYPE_BANNED, null)));
        asSuperadmin().post().uri("/bff/tube/admin/access/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.accessType").isEqualTo("banned");
    }

    @Test
    void timeout_allowedForAdmin() {
        when(access.timeout(eq("bob"), anyLong(), any(), any()))
                .thenReturn(Mono.just(active(TubeAccess.TYPE_BANNED, Instant.now().plusSeconds(3600))));
        asAdmin().post().uri("/bff/tube/admin/access/timeout").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"ttlSeconds\":3600}")
                .exchange().expectStatus().isOk();
    }

    @Test
    void timeout_400WhenTtlNotPositive() {
        asAdmin().post().uri("/bff/tube/admin/access/timeout").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\",\"ttlSeconds\":0}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void grant_400WhenUserSubjectMissing() {
        asAdmin().post().uri("/bff/tube/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void restore_allowedForAdmin() {
        when(access.revoke(eq("bob"), eq(TubeAccess.TYPE_BANNED), any())).thenReturn(Mono.empty());
        asAdmin().delete().uri("/bff/tube/admin/access/banned/bob")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("revoked");
    }

    @Test
    void restore_400WhenAccessTypeUnknown() {
        asAdmin().delete().uri("/bff/tube/admin/access/bogus/bob")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void grant_forbiddenForModTube_governorsAreAdminsOnly() {
        asModTube().post().uri("/bff/tube/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void grant_forbiddenForPlainUser() {
        asUser().post().uri("/bff/tube/admin/access/grant").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"userSubject\":\"bob\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── manage-all (TUBE_MANAGE) ───────────────────────────────────────
    @Test
    void listActive_allowedForSuperadmin() {
        when(access.listActive(any())).thenReturn(Flux.just(active(TubeAccess.TYPE_USE, null)));
        asSuperadmin().get().uri("/bff/tube/superadmin/access")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.access[0].userSubject").isEqualTo("bob");
    }

    @Test
    void listActive_forbiddenForAdmin_manageIsSuperadminOnly() {
        asAdmin().get().uri("/bff/tube/superadmin/access")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void history_allowedForSuperadmin() {
        when(access.historyFor(eq("bob"), any())).thenReturn(Flux.just(
                new TubeAccess("id-2", "default", "bob", TubeAccess.TYPE_BANNED, TubeAccess.STATE_REVOKED,
                        "admin-x", "r", Instant.now(), null, Instant.now())));
        asSuperadmin().get().uri("/bff/tube/superadmin/access/bob/history")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.access[0].state").isEqualTo("revoked");
    }
}
