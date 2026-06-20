package systems.snapdragon.tubebff.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;
import systems.snapdragon.tubebff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * THE LOAD-BEARING test: {@link TubeAccessGuard} is the request-time enforcement that
 * makes the {@code tube_access} overlay NOT inert. It runs over the REAL repo + a
 * multi-brand {@link PrincipalDomain} so the issuer-derived scoping is exercised end to
 * end. Delineated per the test standard — the headline cases the design calls out, with
 * the DEFAULT-DENY / GRANT-ONLY stance that the bare {@code ROLE_TUBE} floor does NOT
 * substitute for a use grant:
 *
 * <ul>
 *   <li><b>DEFAULT-DENY</b>: a principal with NO grant — even one holding ROLE_TUBE /
 *       ROLE_MOD / ROLE_ADMIN — cannot use the tube service.</li>
 *   <li><b>USER-SITUATIONAL — grant ALLOW</b>: a use GRANT lets a plain USER in;
 *       revoking the grant removes use (DENY).</li>
 *   <li><b>CROSS-USER ALLOW+DENY — the BAN precedence (load-bearing)</b>: a ban beats a
 *       grant (ban&gt;grant).</li>
 *   <li><b>TIMEOUT</b>: denies a grantee until {@code expires_at}, then auto-allows
 *       (simulated past vs future expiry) WITHOUT a write.</li>
 *   <li><b>SUPERADMIN</b> is never banned out AND may use WITHOUT a grant (infra,
 *       exempt — no DB read).</li>
 *   <li><b>DOMAIN ISOLATION</b>: a grant/ban in brand X does not affect brand Y.</li>
 *   <li><b>CONCURRENT-CONFLICTING</b>: with BOTH an active grant and an active ban, the ban
 *       wins (precedence is deterministic regardless of row order).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, TubeAccessRepository.class})
class TubeAccessGuardTest {

    @Autowired TubeAccessRepository repo;

    private TubeAccessGuard guard;
    private TubeAccessService service;

    /** Multi-brand registry: brandx + brandy issuers (so issuer -> domain scoping fires). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final PrincipalDomain PD = new PrincipalDomain(MULTI);

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix (see TubeAccessRepositoryTest): the slice tests share one
    // cached context + H2 store, so prefix this class's subjects to avoid collisions.
    private String user(String tag) { return "guard-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        guard = new TubeAccessGuard(repo, PD);
        service = new TubeAccessService(repo, PD);
    }

    /** A JWT-principal Authentication for a brand (issuer) + subject + Casdoor roles. The
     *  guard reads the brand from the issuer ({@link PrincipalDomain}), the subject from
     *  {@code sub}, and SUPERADMIN from the roles. */
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

    private static Authentication plainUser(String issuer, String subject) {
        return principal(issuer, subject);  // ROLE_USER only
    }

    private static void assertAllowed(TubeAccessGuard g, Authentication a) {
        StepVerifier.create(g.assertCanUse(a)).verifyComplete();
    }

    private static void assertDenied(TubeAccessGuard g, Authentication a) {
        StepVerifier.create(g.assertCanUse(a))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
    }

    // ── DEFAULT-DENY — no grant => no use, even for role-holders ──────────────
    @Nested
    class DefaultDeny {

        /** A plain USER is denied by default (no grant). */
        @Test
        void plainUser_withoutGrant_isDenied() {
            assertDenied(guard, plainUser(ISS_X, user("dd-nouser")));
        }

        /** A ROLE_TUBE holder is STILL denied without a grant — the base service role
         *  is the route/connect floor only and does NOT confer use (the stance: there is
         *  no role-qualifies path past default-deny). */
        @Test
        void tubeRoleHolder_withoutGrant_isDenied() {
            assertDenied(guard, principal(ISS_X, user("dd-tube"), "tube"));
        }

        /** Even a MOD+TUBE holder is denied without a grant (use is grant-only; ROLE_TUBE
         *  / ROLE_TUBE_MOD do not lift a user past default-deny). */
        @Test
        void modTubeHolder_withoutGrant_isDenied() {
            assertDenied(guard, principal(ISS_X, user("dd-modtube"), "mod", "tube"));
        }

        /** Even a plain ADMIN is denied use without a grant — ADMIN governs (grants
         *  use to others) but does not by itself hold a use grant. */
        @Test
        void admin_withoutGrant_isDenied() {
            assertDenied(guard, principal(ISS_X, user("dd-admin"), "admin"));
        }
    }

    // ── USER-SITUATIONAL — grant ALLOW / revoke DENY ──────────────────────────
    @Nested
    class GrantAllow {

        /** A GRANT lets a plain USER use the tube service (ALLOW — the load-bearing grant
         *  path). */
        @Test
        void grantedUser_gainsUse() {
            String u = user("ga-granted");
            Authentication user = plainUser(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");

            assertDenied(guard, user);                 // before grant (default-deny)
            service.grant(u, "enable tube", adminX).block();
            assertAllowed(guard, user);                // after grant — ALLOW
        }

        /** Revoking the grant removes use (DENY). */
        @Test
        void revokingGrant_removesUse() {
            String u = user("ga-revoke");
            Authentication user = plainUser(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.grant(u, null, adminX).block();
            assertAllowed(guard, user);

            service.revoke(u, TubeAccess.TYPE_USE, adminX).block();
            assertDenied(guard, user);                 // grant lifted — DENY
        }
    }

    // ── CROSS-USER ALLOW+DENY — the BAN precedence (LOAD-BEARING) ──────────────
    @Nested
    class BanPrecedence {

        /** THE load-bearing case: a ban beats a grant — an active grant + an active ban
         *  => denied (ban>grant). */
        @Test
        void ban_beatsGrant() {
            String u = user("bp-bangrant");
            Authentication user = plainUser(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.grant(u, null, adminX).block();
            assertAllowed(guard, user);                // grant ALLOW

            service.ban(u, "abuse", adminX).block();   // now also banned
            assertDenied(guard, user);                 // ban wins (precedence)
        }

        /** A ban denies even a would-be grantee who ALSO holds a service role — the ban is
         *  absolute for a non-superadmin. */
        @Test
        void ban_deniesGranteeWithRole() {
            String u = user("bp-rolegrant");
            Authentication granteeWithRole = principal(ISS_X, u, "tube");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.grant(u, null, adminX).block();
            assertAllowed(guard, granteeWithRole);     // grant ALLOW (role is irrelevant)

            service.ban(u, "abuse", adminX).block();
            assertDenied(guard, granteeWithRole);      // BANNED despite grant + role
        }
    }

    // ── TIMEOUT (denies until expiry, then auto-allows) ───────────────────────
    @Nested
    class Timeout {

        /** An ACTIVE timeout (future expiry) denies a grantee. */
        @Test
        void activeTimeout_denies() {
            String u = user("to-active");
            Authentication user = plainUser(ISS_X, u);
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.grant(u, null, adminX).block();
            assertAllowed(guard, user);                // uses by grant pre-timeout

            service.timeout(u, 3600, "cooldown", adminX).block();  // future expiry
            assertDenied(guard, user);                 // timed out
        }

        /** An EXPIRED timeout auto-restores (the guard ignores a past expires_at) WITHOUT a
         *  write — the row is still state=active in the DB but no longer effective; the
         *  underlying use grant is back in effect. */
        @Test
        void expiredTimeout_autoRestores_withoutWrite() {
            String u = user("to-expired");
            Authentication user = plainUser(ISS_X, u);

            // A standing use grant + a 'banned' row whose expires_at is in the PAST.
            repo.insertActive(u, TubeAccess.TYPE_USE, null, "live", "admin-x", "brandx").block();
            Instant past = Instant.now().minusSeconds(60);
            repo.insertActive(u, TubeAccess.TYPE_BANNED, past, "old", "admin-x", "brandx").block();

            // The banned row is still ACTIVE in the table (no expiry write happened)...
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").block()).isNotNull();
            // ...but the guard treats the lapsed timeout as inactive => use auto-restored.
            assertAllowed(guard, user);
        }
    }

    // ── SUPERADMIN (never banned out; may use without a grant) ─────────────────
    @Nested
    class Superadmin {

        /** SUPERADMIN is exempt from the overlay — it may use WITHOUT a grant. */
        @Test
        void superadmin_usesWithoutGrant() {
            assertAllowed(guard, principal(ISS_X, user("su-nogrant"), "superadmin"));
        }

        /** SUPERADMIN is never banned out — even an active ban on its subject does not
         *  deny it (infra control plane, no DB read). */
        @Test
        void superadmin_isNeverBannedOut() {
            String u = user("su-ban");
            Authentication su = principal(ISS_X, u, "superadmin");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.ban(u, "ignored-for-superadmin", adminX).block();

            assertAllowed(guard, su);                  // banned row present, but SUPERADMIN uses
        }
    }

    // ── DOMAIN ISOLATION (a grant/ban in X does not affect Y) ─────────────────
    @Nested
    class DomainIsolation {

        /** A grant in brand X does NOT let the same subject use in brand Y. */
        @Test
        void grantInBrandX_doesNotGrantBrandY() {
            String u = user("di-grant");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            service.grant(u, null, adminX).block();

            assertAllowed(guard, plainUser(ISS_X, u));  // granted in X
            assertDenied(guard, plainUser(ISS_Y, u));   // NOT granted in Y (default-deny)
        }

        /** A ban on a subject in brand X does NOT deny the SAME subject's grant in brand Y
         *  (the override is brand-scoped). */
        @Test
        void banInBrandX_doesNotDenyBrandY() {
            String u = user("di-ban");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            Authentication adminY = principal(ISS_Y, "admin-y", "admin");
            service.grant(u, null, adminY).block();     // a grant in brand Y
            service.ban(u, "x-only", adminX).block();   // a ban in brand X

            // The same subject still uses in brand Y (brand Y has no ban row).
            assertAllowed(guard, plainUser(ISS_Y, u));
            // ...and is denied in brand X (banned there, and no grant there anyway).
            assertDenied(guard, plainUser(ISS_X, u));
        }
    }

    // ── CONCURRENT-CONFLICTING (grant + ban -> ban wins, order-independent) ────
    @Nested
    class ConcurrentConflicting {

        /** With BOTH an active grant AND an active ban present for the same principal, the
         *  guard's precedence is deterministic — the ban always wins regardless of which
         *  row the DB returns first. */
        @Test
        void concurrentGrantAndBan_banWins() {
            String u = user("cc-both");
            Authentication adminX = principal(ISS_X, "admin-x", "admin");
            // Both overrides active at once (different access_type, so both coexist).
            service.grant(u, null, adminX).block();
            service.ban(u, "abuse", adminX).block();

            assertThat(repo.activeFor(u, "brandx").collectList().block()).hasSize(2);
            assertDenied(guard, plainUser(ISS_X, u));   // ban wins over grant
        }
    }
}
