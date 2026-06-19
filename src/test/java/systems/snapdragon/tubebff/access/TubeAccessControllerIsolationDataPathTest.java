package systems.snapdragon.tubebff.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;
import systems.snapdragon.tubebff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The wave-2c DATA-PATH isolation gap closer for {@link TubeAccessController}.
 *
 * <p>The existing {@code TubeAccessControllerTest} (a {@code @WebFluxTest}) MOCKS
 * {@link TubeAccessService} entirely — it proves the controller wiring + the coarse
 * path-gate / role contract, but it can prove NOTHING about the per-domain isolation
 * because the only thing standing between brand X and brand Y (the
 * {@code AND domain = :domain} WHERE predicate) is mocked away. This class closes that
 * gap by driving the controller through the REAL service → REAL repository (H2 with the
 * production Liquibase {@code 004-tube-access} changelog) → REAL {@link PrincipalDomain},
 * so the cross-brand DENY is proven at the data path, not re-derived from an
 * {@code ArgumentCaptor}.
 *
 * <p>The acting principal's brand is derived SERVER-SIDE from the validated token issuer
 * ({@link PrincipalDomain#forScope}); a brand-Y admin's domain is {@code brandy}, so its
 * reads/mutations carry {@code AND domain = 'brandy'} and a brand-X override is INVISIBLE
 * — the controller cannot revoke it, list it, or read its history. These are
 * mutation-resistant: each DENY pairs the controller's observable HTTP outcome with a
 * direct repository re-read proving the targeted brand-X row was NOT mutated (would FAIL
 * if the domain predicate were dropped — the brand-Y admin would then revoke the brand-X
 * row and the re-read would be empty).
 *
 * <table>
 *   <caption>Delineation</caption>
 *   <tr><th>Category</th><th>Case</th></tr>
 *   <tr><td>USER-SITUATIONAL (ALLOW)</td><td>own-brand admin grants/lists/revokes its
 *       own brand's row</td></tr>
 *   <tr><td>CROSS-USER (DENY isolation)</td><td>brand-Y admin's revoke of a brand-X ban
 *       is a no-op (the row survives); brand-Y admin's list/history never sees brand-X's
 *       row</td></tr>
 *   <tr><td>CROSS-USER (ALLOW bypass)</td><td>SUPERADMIN (null scope) sees+revokes every
 *       brand</td></tr>
 * </table>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, TubeAccessRepository.class})
class TubeAccessControllerIsolationDataPathTest {

    @Autowired TubeAccessRepository repo;

    private TubeAccessController controller;
    private TubeAccessService service;

    /** Multi-brand registry: brandx + brandy issuers (so issuer → domain scoping fires). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final PrincipalDomain PD = new PrincipalDomain(MULTI);

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix (see TubeAccessRepositoryTest): the @DataR2dbcTest slice tests
    // share one cached context + H2 store, so prefix this class's subjects to avoid
    // collisions with the repo/service/guard slice tests.
    private String user(String tag) { return "ctlr-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        service = new TubeAccessService(repo, PD);
        controller = new TubeAccessController(service);
    }

    /** A JWT-principal Authentication for a brand (issuer) + subject + Casdoor roles —
     *  the same shape the service/guard slice tests use. The controller's service derives
     *  the brand from the issuer and the granted_by from the subject. */
    private static Authentication principal(String issuer, String subject, String... roles) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).claim("iss", issuer).issuer(issuer)
                .claim("roles", List.of(roles)).build();
        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) auths.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()));
        return new UsernamePasswordAuthenticationToken(jwt, "n/a", auths);
    }

    private static TubeAccessDto.GrantOrBan grantBody(String userSubject, String reason) {
        return new TubeAccessDto.GrantOrBan(userSubject, reason);
    }

    // ── USER-SITUATIONAL (ALLOW) — own-brand admin governs its own brand ───────
    @Nested
    class OwnBrandAllow {

        @Test
        void adminGrant_writesActiveRow_visibleToOwnBrandList() {
            String u = user("allow-grant");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");

            ResponseEntity<TubeAccessDto.Access> resp =
                    controller.grant(grantBody(u, "enable"), adminX).block();
            assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(resp.getBody().accessType()).isEqualTo(TubeAccess.TYPE_USE);

            // Data-path proof: the row exists in brand X.
            assertThat(repo.findActive(u, TubeAccess.TYPE_USE, "brandx").block()).isNotNull();
        }

        @Test
        void adminRevoke_ofOwnBrandRow_liftsIt() {
            String u = user("allow-revoke");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            controller.ban(grantBody(u, "bad"), adminX).block();
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").block()).isNotNull();

            ResponseEntity<Map<String, Object>> resp =
                    controller.revoke(TubeAccess.TYPE_BANNED, u, adminX).block();
            assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(resp.getBody().get("state")).isEqualTo("revoked");
            // Lifted in brand X.
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").blockOptional()).isEmpty();
        }
    }

    // ── CROSS-USER (DENY isolation) — the un-mocked per-domain WHERE proof ──────
    @Nested
    class CrossBrandDeny {

        /**
         * The end-to-end cross-brand 403-equivalent at the DATA PATH: a brand-Y admin
         * passes the {@code /bff/tube/admin/**} path-gate + TUBE_GOVERN role check (it is
         * a legitimate admin), but its server-derived scope is {@code brandy}, so the
         * service's {@code findActive(..., 'brandy')} cannot see the brand-X ban and the
         * revoke is a NO-OP. The brand-X override SURVIVES — isolation enforced by the
         * WHERE predicate, not by a role gate.
         *
         * <p>Mutation-resistant: if the {@code AND domain = :domain} predicate were
         * dropped, the brand-Y admin's revoke would lift the brand-X row and the re-read
         * below would be empty → this test FAILS.
         */
        @Test
        void brandYAdmin_cannotRevokeBrandXOverride_rowSurvives() {
            String u = user("deny-revoke");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            Authentication adminY = principal(ISS_Y, "admin-y", "admin");

            // A ban placed by brand X (its own brand).
            controller.ban(grantBody(u, "x-ban"), adminX).block();
            TubeAccess before = repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").block();
            assertThat(before).isNotNull();

            // Brand Y admin tries to lift it — the controller returns 200 "revoked" (the
            // CAS simply matched nothing in its scope), but the brand-X row is untouched.
            ResponseEntity<Map<String, Object>> resp =
                    controller.revoke(TubeAccess.TYPE_BANNED, u, adminY).block();
            assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);

            // DATA-PATH ISOLATION PROOF: brand-X's ban is still active, same row id.
            TubeAccess after = repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").block();
            assertThat(after).as("brand-Y admin must NOT be able to lift brand-X's ban").isNotNull();
            assertThat(after.id()).isEqualTo(before.id());
            assertThat(after.state()).isEqualTo(TubeAccess.STATE_ACTIVE);

            // ...and brand X (the real owner) CAN lift it (ALLOW completes the pair).
            controller.revoke(TubeAccess.TYPE_BANNED, u, adminX).block();
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").blockOptional()).isEmpty();
        }

        /**
         * The MANAGE list-all read is domain-scoped too: a brand-Y SUPERADMIN-less reader
         * (here we use the listActive surface which scopes to the actor's brand) never
         * sees another brand's row. We drive listActive with a brand-scoped principal
         * (the controller method's @PreAuthorize is SUPERADMIN, but the SCOPE under test
         * is the service's WHERE predicate keyed off the principal's issuer — so we assert
         * the data-path scoping directly via the controller method).
         */
        @Test
        void listActive_brandYScope_neverSeesBrandXRow() {
            String u = user("deny-list");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            // A brand-Y principal carrying SUPERADMIN would be unscoped (null) — to test the
            // SCOPED read we use a brand-Y admin token; PrincipalDomain.forScope maps it to
            // "brandy" (non-superadmin), so the list is scoped to brand Y.
            Authentication readerY = principal(ISS_Y, "reader-y", "admin");

            controller.grant(grantBody(u, "x-grant"), adminX).block();

            TubeAccessDto.AccessList listY = controller.listActive(readerY).block();
            assertThat(listY.access())
                    .as("a brand-Y scoped read must never surface brand-X's override")
                    .noneSatisfy(a -> assertThat(a.userSubject()).isEqualTo(u));

            // The brand-X owner DOES see it via a brand-X scoped read (ALLOW side).
            Authentication readerX = principal(ISS_X, "reader-x", "admin");
            TubeAccessDto.AccessList listX = controller.listActive(readerX).block();
            assertThat(listX.access())
                    .anySatisfy(a -> assertThat(a.userSubject()).isEqualTo(u));
        }

        /** The audit HISTORY read is brand-scoped: a brand-Y reader sees no history for a
         *  user whose only override lives in brand X. */
        @Test
        void history_brandYScope_neverSeesBrandXRow() {
            String u = user("deny-hist");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            Authentication readerY = principal(ISS_Y, "reader-y", "admin");

            controller.ban(grantBody(u, "x-ban"), adminX).block();

            TubeAccessDto.AccessList histY = controller.history(u, readerY).block();
            assertThat(histY.access())
                    .as("brand-Y must see no audit history of a brand-X-only override")
                    .isEmpty();

            // brand-X owner sees its own history.
            Authentication readerX = principal(ISS_X, "reader-x", "admin");
            assertThat(controller.history(u, readerX).block().access()).isNotEmpty();
        }
    }

    // ── CROSS-USER (ALLOW bypass) — SUPERADMIN is cross-domain ─────────────────
    @Nested
    class SuperadminBypass {

        /** SUPERADMIN (forScope → null) reads every brand: it sees a brand-X override and
         *  can revoke it. The bypass is the deliberate counterpart of the brand-Y DENY. */
        @Test
        void superadmin_seesAndRevokesAnotherBrandsRow() {
            String u = user("su-bypass");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            Authentication su = principal(ISS_Y, "root", "superadmin");  // issuer irrelevant for SU

            controller.ban(grantBody(u, "x-ban"), adminX).block();

            // SUPERADMIN's history read (null scope) surfaces the brand-X row.
            assertThat(controller.history(u, su).block().access())
                    .anySatisfy(a -> assertThat(a.domain()).isEqualTo("brandx"));

            // ...and it can lift it cross-domain.
            controller.revoke(TubeAccess.TYPE_BANNED, u, su).block();
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").blockOptional()).isEmpty();
        }
    }
}
