package systems.snapdragon.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccess;
import systems.snapdragon.tubebff.access.TubeAccessController;
import systems.snapdragon.tubebff.access.TubeAccessService;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.testsupport.TestIssuer;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * WAVE-2 role-matrix + cross-brand HTTP slice for {@link TubeAccessController}, driven by
 * REAL per-brand JWTs through the production filter chain + per-brand resolver.
 *
 * <p>The EXISTING {@code TubeAccessControllerTest} proves the role gates with directly
 * STAMPED authorities ({@code mockJwt().authorities(...)}). This complementary slice
 * proves the SAME gates fire when the role authority is DERIVED by the real
 * {@code CasdoorAuthorities} converter from the validated {@code roles} claim — i.e. it
 * exercises the JWT-decode → authority-mapping → @PreAuthorize chain end-to-end — AND adds
 * the missing HTTP-boundary facts:
 *
 * <ul>
 *   <li><b>Role matrix (DERIVED roles):</b> a brand-X ADMIN reaches the govern surface
 *       ({@code /bff/tube/admin/access/grant}); a brand-X plain USER (no ADMIN) is 403;
 *       the SUPERADMIN-only manage surface ({@code /bff/tube/superadmin/access}) 403s a
 *       brand-X ADMIN and 200s a brand-X SUPERADMIN.</li>
 *   <li><b>Domain is issuer-derived, not forgeable:</b> the {@code Authentication} that
 *       reaches {@code TubeAccessService} carries the issuer-derived {@code DOMAIN_brandx}
 *       (captured) — the service scopes on THAT, never on a request field. A brand-Y admin
 *       carries {@code DOMAIN_brandy}, never {@code DOMAIN_brandx}.</li>
 *   <li><b>401 unauthenticated</b> + <b>401 unknown-issuer fail-closed</b> on the govern
 *       surface (the existing controller test asserts neither).</li>
 * </ul>
 *
 * <p>The per-domain WHERE predicate inside {@code TubeAccessService} is the already-tested
 * service layer; here we assert only the HTTP boundary + that the authority the service is
 * handed is the cryptographically-validated brand.
 */
class TubeAccessControllerCrossBrandSliceTest extends MultiIssuerControllerSliceSupport {

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;

    private TubeAccessService access;       // mocked — we capture the Authentication it is handed
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        DomainRegistry registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        assertThat(registry.isMultiIssuer()).isTrue();

        access = mock(TubeAccessService.class);
        TubeAccessController controller = new TubeAccessController(access);

        client = sliceClient(registry,
                new Object[]{new ApiExceptionHandler()},
                controller);
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    private static TubeAccess activeUse() {
        return new TubeAccess("id-1", "brandx", "bob", TubeAccess.TYPE_USE, TubeAccess.STATE_ACTIVE,
                "admin-x", "reason", Instant.now(), null, null);
    }

    private static final String GRANT_BODY = "{\"userSubject\":\"bob\",\"reason\":\"enable\"}";

    // ── role matrix on the govern surface (roles DERIVED by the real converter) ──

    /** A brand-X ADMIN (roles claim → ROLE_ADMIN by the converter) reaches the govern
     *  grant; AND the Authentication handed to the service carries the issuer-derived
     *  DOMAIN_brandx — the brand the service scopes on, never a request field. */
    @Test
    void grant_brandXAdmin_allowed_andServiceSeesIssuerDerivedBrand() {
        when(access.grant(eq("bob"), any(), any())).thenReturn(Mono.just(activeUse()));

        String token = brandX.mint("admin-x", List.of("admin"));
        client.post().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.accessType").isEqualTo("use");

        ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(access).grant(eq("bob"), any(), auth.capture());
        List<String> authorities = auth.getValue().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
        assertThat(authorities)
                .as("the service scopes on the issuer-derived brand carried on the Authentication")
                .contains("DOMAIN_brandx", "ROLE_ADMIN")
                .doesNotContain("DOMAIN_brandy", "DOMAIN_default");
    }

    /** A brand-Y ADMIN reaches grant too, but the service is handed DOMAIN_brandy — the
     *  two brands' admins never collide on a domain even with identical request bodies. */
    @Test
    void grant_brandYAdmin_serviceSeesBrandY_notBrandX() {
        when(access.grant(eq("bob"), any(), any())).thenReturn(Mono.just(activeUse()));

        String token = brandY.mint("admin-y", List.of("admin"));
        client.post().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isOk();

        ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(access).grant(eq("bob"), any(), auth.capture());
        List<String> authorities = auth.getValue().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
        assertThat(authorities).contains("DOMAIN_brandy").doesNotContain("DOMAIN_brandx");
    }

    /** A brand-X plain USER (no admin role in the claim) is FORBIDDEN the govern grant —
     *  the {@code /bff/tube/admin/**} path gate + @PreAuthorize require ADMIN|SUPERADMIN. */
    @Test
    void grant_brandXPlainUser_is403_roleMatrixDeny() {
        String token = brandX.mint("alice", List.of());   // only the ROLE_USER floor
        client.post().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isForbidden();
    }

    /** A brand-X MOD+TUBE is FORBIDDEN the govern grant — governors are ADMIN-tier; MOD is
     *  a documented SIBLING of ADMIN (no MOD→ADMIN edge), so the admin prefix denies it. */
    @Test
    void grant_brandXModTube_is403_modIsNotGovernor() {
        String token = brandX.mint("mod-1", List.of("mod", "tube"));
        client.post().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── manage-all surface — SUPERADMIN only (DERIVED roles) ─────────────────────

    /** The SUPERADMIN-only manage surface FORBIDS a brand-X ADMIN (manage > govern). */
    @Test
    void listActive_brandXAdmin_is403_manageIsSuperadminOnly() {
        String token = brandX.mint("admin-x", List.of("admin"));
        client.get().uri("/bff/tube/superadmin/access")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden();
    }

    /** A brand-X SUPERADMIN reaches the manage surface (roles claim → ROLE_SUPERADMIN). */
    @Test
    void listActive_brandXSuperadmin_allowed() {
        when(access.listActive(any())).thenReturn(Flux.just(activeUse()));
        String token = brandX.mint("root", List.of("superadmin"));
        client.get().uri("/bff/tube/superadmin/access")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.access[0].userSubject").isEqualTo("bob");
    }

    // ── fail-closed neighbours ───────────────────────────────────────────────────

    /** No bearer ⇒ 401 (the existing TubeAccessControllerTest asserts no 401 at all). */
    @Test
    void grant_noBearer_is401() {
        client.post().uri("/bff/tube/admin/access/grant")
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** A correctly-signed token from an UNLISTED issuer ⇒ 401 fail-closed, even carrying a
     *  forged {@code superadmin} role — the resolver yields no manager before any authority
     *  is emitted, so the role never matters. */
    @Test
    void grant_rogueIssuer_is401_failClosed_evenWithSuperadminRole() {
        String token = rogue.mint("mallory", List.of("superadmin", "admin"));
        client.post().uri("/bff/tube/admin/access/grant")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue(GRANT_BODY)
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
