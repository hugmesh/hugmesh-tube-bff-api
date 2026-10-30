package net.hugmesh.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.tubebff.access.TubeAccess;
import net.hugmesh.tubebff.access.TubeAccessGuard;
import net.hugmesh.tubebff.access.TubeAccessRepository;
import net.hugmesh.tubebff.download.StorageUsage;
import net.hugmesh.tubebff.download.StorageUsageService;
import net.hugmesh.tubebff.download.TubeStorageBudgetController;
import net.hugmesh.tubebff.media.TubeMediaController;
import net.hugmesh.tubebff.media.TubeMediaTokenService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.tubebff.security.PrincipalDomain;
import net.hugmesh.tubebff.testsupport.TestIssuer;
import net.hugmesh.tubebff.web.ApiExceptionHandler;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * WAVE-2 controller/filter-layer HTTP authz slice — the missing HTTP-boundary proof that
 * the per-brand DOMAIN decision is taken from the CRYPTOGRAPHICALLY-VALIDATED ISSUER, not
 * a request field. Drives REAL brand-X / brand-Y JWTs (minted by an in-process
 * {@link TestIssuer}) THROUGH the production {@code SecurityConfig.filterChain} + the
 * production {@code TenancyResourceServerConfig} per-brand resolver INTO the REAL
 * controllers — so the assertions are the actual controller HTTP responses.
 *
 * <p>Distinct from the existing slice tests, which stamp authorities directly via
 * {@code mockJwt().authorities(...)} (bypassing the issuer→domain derivation) and from
 * PR #7's multi-issuer slice (which routes only a synthetic {@code whoami} echo). Here a
 * brand-X token actually reaches {@code TubeMediaController}/{@code TubeStorageBudgetController}
 * and the controller's OWN domain check fires.
 *
 * <table>
 *   <caption>Mission pillars covered</caption>
 *   <tr><th>#</th><th>Pillar</th><th>Assertion</th><th>Category</th></tr>
 *   <tr><td>1</td><td>controller cross-brand DENY</td>
 *       <td>brand-X token signing media for {@code /brandy/...} → 403; the signed URL of
 *           a legit sign embeds the issuer-derived brand, never a request value</td>
 *       <td>CROSS-USER DENY (isolation)</td></tr>
 *   <tr><td>2</td><td>owner==subject</td>
 *       <td>alice's brand-X token signing for bob → 403; for herself → 200</td>
 *       <td>CROSS-USER DENY</td></tr>
 *   <tr><td>3</td><td>role matrix</td>
 *       <td>budget write is ADMIN|SUPERADMIN; the written domain is the admin's
 *           issuer-derived brand (captured), never the request body</td>
 *       <td>MULTIUSER-SITUATIONAL + ALLOW/DENY</td></tr>
 *   <tr><td>4</td><td>forged-claims defense</td>
 *       <td>brand-X token carrying {@code permissions:["DOMAIN_brandy","ROLE_SUPERADMIN"]}
 *           is stripped by the converter → still cannot cross brands / escalate</td>
 *       <td>CROSS-USER DENY (injection)</td></tr>
 * </table>
 */
class ControllerCrossBrandAuthzSliceTest extends MultiIssuerControllerSliceSupport {

    /** A fixed, obviously-fake 32-byte HMAC key (the same fixture
     *  {@code TubeMediaControllerTest}/{@code TestProfileKeys} use). NOT a secret. */
    private static final String MEDIA_KEY = Base64.getEncoder()
            .encodeToString("01234567890123456789012345678901".getBytes());

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;          // correctly-signed, but NOT in the registry

    private DomainRegistry registry;
    private StorageUsageService usage;          // mocked — we capture the domain it is asked to write

    // The real controllers under test.
    private TubeMediaController mediaController;
    private TubeStorageBudgetController budgetController;

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Registry trusts ONLY brandX + brandY (rogue deliberately omitted → its tokens 401).
        registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        assertThat(registry.isMultiIssuer()).as("two trusted issuers ⇒ multi-issuer mode").isTrue();

        // TubeMediaController: a REAL token service (signs for real — the URL it returns
        // is asserted to embed the issuer-derived domain, never a request value) + a REAL
        // DEFAULT-DENY use gate over a mocked repo. Signing is a USE of the service, so it
        // is now overlay-gated; this slice exercises the ISSUER→DOMAIN + owner walls, so the
        // use overlay is defaulted to an active GRANT for the caller (the dedicated
        // default-deny/ban proofs live in TubeMediaSecuritySliceTest + TubeMediaControllerTest).
        TubeAccessRepository accessRepo = mock(TubeAccessRepository.class);
        when(accessRepo.activeFor(any(), any())).thenAnswer(inv -> Flux.just(
                new TubeAccess("use-" + inv.getArgument(0), inv.getArgument(1), inv.getArgument(0),
                        TubeAccess.TYPE_USE, TubeAccess.STATE_ACTIVE, "admin", "enable",
                        Instant.now(), null, null)));
        TubeAccessGuard useGate = new TubeAccessGuard(accessRepo, new PrincipalDomain(registry));
        mediaController = new TubeMediaController(new TubeMediaTokenService(MEDIA_KEY), useGate);

        // TubeStorageBudgetController: a REAL PrincipalDomain (so the brand is derived
        // SERVER-SIDE from the validated issuer) + a mocked service to capture the domain.
        usage = mock(StorageUsageService.class);
        budgetController = new TubeStorageBudgetController(usage, new PrincipalDomain(registry));

        // The production @RestControllerAdvice MUST be registered so a controller's
        // Mono.error(ApiException.forbidden(...)) renders as 403 (the deployed behaviour),
        // not the bare-bindToController 500.
        client = sliceClient(registry,
                new Object[]{new ApiExceptionHandler()},
                mediaController, budgetController);
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PILLAR 1 — controller cross-brand DENY (brand-X token cannot read brand-Y data)
    // ─────────────────────────────────────────────────────────────────────────

    /** A brand-X user (issuer→DOMAIN_brandx) signs a media URL embedding brand-Y's path
     *  prefix. The controller's wall-2 domain check (path domain == JWT-derived domain)
     *  rejects it 403 — a brand-X token can NEVER mint a URL into brand-Y's content. */
    @Test
    void media_brandXToken_signingIntoBrandY_is403_crossBrandDeny() {
        String token = brandX.mint("alice", List.of("tube"));
        client.get().uri("/bff/tube/media/sign?path=/brandy/alice/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    /** The mirror direction: a brand-Y user signing into brand-X is also 403 — isolation
     *  holds symmetrically. */
    @Test
    void media_brandYToken_signingIntoBrandX_is403_crossBrandDeny() {
        String token = brandY.mint("bob", List.of("tube"));
        client.get().uri("/bff/tube/media/sign?path=/brandx/bob/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden();
    }

    /** A legit same-brand sign succeeds AND the signed URL embeds the issuer-derived
     *  brand ({@code domain=brandx}) — proving the controller signs against the
     *  cryptographically-validated brand, NOT a value the caller supplied. */
    @Test
    void media_brandXToken_signingOwnBrand_is200_andUrlEmbedsIssuerDerivedDomain() {
        String token = brandX.mint("alice", List.of("tube"));
        client.get().uri("/bff/tube/media/sign?path=/brandx/alice/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.url").value((String url) ->
                        assertThat(url)
                                .startsWith("/tube/content/brandx/alice/videos/vid.mp4?")
                                .contains("sub=alice")
                                .contains("domain=brandx")
                                .doesNotContain("domain=brandy"))
                .jsonPath("$.expiresAt").exists();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PILLAR 2 — owner==subject on the user-scoped media endpoint
    // ─────────────────────────────────────────────────────────────────────────

    /** alice (brand-X) tries to sign a URL for eve's content IN HER OWN BRAND. The
     *  subject wall (path subject == jwt.subject) rejects it 403 — owner-scope holds even
     *  within a single brand. */
    @Test
    void media_wrongOwnerSameBrand_is403_ownerEqualsSubject() {
        String token = brandX.mint("alice", List.of("tube"));
        client.get().uri("/bff/tube/media/sign?path=/brandx/eve/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").exists();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PILLAR 3 — role matrix + server-derived brand on the admin budget surface
    // ─────────────────────────────────────────────────────────────────────────

    /** A brand-X ADMIN sets a target user's budget. The write MUST be scoped to the
     *  admin's issuer-derived brand ({@code brandx}) — the request body carries only the
     *  TARGET subject + bytes, NEVER a domain. We capture the domain the service is asked
     *  to write and assert it is the issuer-derived brand, not anything forgeable. */
    @Test
    void budget_adminWrite_isScopedToIssuerDerivedBrand_notRequestField() {
        when(usage.setBudget(eq("bob"), eq("brandx"), anyLong()))
                .thenReturn(Mono.just(new StorageUsage("brandx", "bob", 0L, 5000L, Instant.now())));

        String token = brandX.mint("admin-x", List.of("admin"));
        client.post().uri("/bff/tube/admin/storage-budget")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.userSubject").isEqualTo("bob");

        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        verify(usage).setBudget(eq("bob"), domain.capture(), eq(5000L));
        assertThat(domain.getValue())
                .as("the budget write domain is the admin's issuer-derived brand")
                .isEqualTo("brandx");
    }

    /** A brand-Y ADMIN writing the SAME target subject lands in brand-Y — the two brands'
     *  admins never collide on a shared domain even with identical request bodies. This is
     *  the cross-brand isolation of the admin write plane. */
    @Test
    void budget_brandYAdminWrite_isScopedToBrandY_notBrandX() {
        when(usage.setBudget(eq("bob"), eq("brandy"), anyLong()))
                .thenReturn(Mono.just(new StorageUsage("brandy", "bob", 0L, 5000L, Instant.now())));

        String token = brandY.mint("admin-y", List.of("admin"));
        client.post().uri("/bff/tube/admin/storage-budget")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .exchange()
                .expectStatus().isOk();

        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        verify(usage).setBudget(eq("bob"), domain.capture(), anyLong());
        assertThat(domain.getValue()).isEqualTo("brandy");
    }

    /** A plain ROLE_TUBE user (brand-X) is FORBIDDEN the admin budget surface — the
     *  {@code /bff/tube/admin/**} path gate (and the method @PreAuthorize) require
     *  ADMIN|SUPERADMIN. Role matrix DENY edge, asserted through the real filter chain. */
    @Test
    void budget_plainTubeUser_is403_roleMatrixDeny() {
        String token = brandX.mint("alice", List.of("tube"));
        client.post().uri("/bff/tube/admin/storage-budget")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .exchange()
                .expectStatus().isForbidden();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PILLAR 4 — forged-claims defense (converter reserved-prefix guard end-to-end)
    // ─────────────────────────────────────────────────────────────────────────

    /** A brand-X token carrying a FORGED {@code permissions:["DOMAIN_brandy"]} cannot
     *  acquire brand-Y scope: the converter's reserved-prefix guard drops the injected
     *  {@code DOMAIN_} permission, so the principal stays {@code DOMAIN_brandx} and the
     *  media controller still rejects a brand-Y path 403. This is the escalation the guard
     *  exists to stop, asserted at the controller HTTP boundary. */
    @Test
    void media_forgedDomainPermission_cannotCrossToBrandY() {
        String token = brandX.mintWithClaims("alice", java.util.Map.of(
                "roles", List.of(java.util.Map.of("name", "tube")),
                "permissions", List.of("DOMAIN_brandy"),
                "name", "alice"));
        // Forged brand-Y path is still rejected — the injected DOMAIN_brandy never took.
        client.get().uri("/bff/tube/media/sign?path=/brandy/alice/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden();
    }

    /** Same token, but signing its OWN (genuine) brand-X path still succeeds — proving the
     *  forged permission neither escalated NOR broke the legitimate path: the genuine
     *  issuer-derived {@code DOMAIN_brandx} survives. */
    @Test
    void media_forgedDomainPermission_genuineBrandStillWorks() {
        String token = brandX.mintWithClaims("alice", java.util.Map.of(
                "roles", List.of(java.util.Map.of("name", "tube")),
                "permissions", List.of("DOMAIN_brandy"),
                "name", "alice"));
        client.get().uri("/bff/tube/media/sign?path=/brandx/alice/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.url").value((String url) ->
                        assertThat(url).contains("domain=brandx").doesNotContain("domain=brandy"));
    }

    /** A brand-X token carrying a FORGED {@code permissions:["ROLE_SUPERADMIN"]} cannot
     *  reach the SUPERADMIN-exempt media bypass or any escalated surface: the converter
     *  drops the reserved {@code ROLE_} permission, so the principal is NOT superadmin and
     *  still cannot mint a brand-Y URL. (A genuine SUPERADMIN role would come from the
     *  {@code roles} claim; a permission string can never forge it.) */
    @Test
    void media_forgedSuperadminPermission_doesNotEscalate() {
        String token = brandX.mintWithClaims("alice", java.util.Map.of(
                "roles", List.of(java.util.Map.of("name", "tube")),
                "permissions", List.of("ROLE_SUPERADMIN"),
                "name", "alice"));
        client.get().uri("/bff/tube/media/sign?path=/brandy/alice/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isForbidden();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fail-closed neighbours — 401 unauthenticated + unknown-issuer
    // ─────────────────────────────────────────────────────────────────────────

    /** No bearer ⇒ 401 at the resource-server filter, before any controller runs. */
    @Test
    void media_noBearer_is401() {
        client.get().uri("/bff/tube/media/sign?path=/brandx/alice/videos/vid.mp4")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** A correctly-signed token from an issuer NOT in the registry (the rogue Casdoor)
     *  ⇒ 401 fail-closed — the resolver yields no manager, so authentication fails BEFORE
     *  any authority is emitted. No default-accept path lets an unlisted brand in. */
    @Test
    void media_rogueIssuerToken_is401_failClosed() {
        String token = rogue.mint("mallory", List.of("tube", "admin", "superadmin"));
        client.get().uri("/bff/tube/media/sign?path=/brandx/mallory/videos/vid.mp4")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** Same unknown-issuer token against the admin budget write ⇒ 401 — a rogue brand
     *  cannot reach the admin write plane regardless of its forged roles. */
    @Test
    void budget_rogueIssuerToken_is401_failClosed() {
        String token = rogue.mint("mallory", List.of("admin"));
        client.post().uri("/bff/tube/admin/storage-budget")
                .headers(h -> h.setBearerAuth(token))
                .header("Content-Type", "application/json")
                .bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":5000}")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
