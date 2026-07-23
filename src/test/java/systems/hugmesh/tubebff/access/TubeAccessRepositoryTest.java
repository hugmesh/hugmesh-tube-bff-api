package systems.hugmesh.tubebff.access;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.tubebff.support.PostgresSliceTestConfig;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link TubeAccessRepository} against H2 (PostgreSQL-compat) with
 * the REAL Liquibase {@code 004-tube-access} changelog. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — insert active grant/ban round-trips; CAS active->revoked
 *       stamps revoked_at and is the only transition (the row is RETAINED = audit, never
 *       deleted); a timed ban carries a future expires_at.</li>
 *   <li><b>CROSS-USER (DENY isolation + domain isolation)</b> — an override in brand X is
 *       invisible to brand Y's scope; findActive is brand-scoped; SUPERADMIN (null domain)
 *       reads every brand's.</li>
 *   <li><b>CONCURRENT-CONFLICTING</b> — many concurrent revokes of one row: exactly one
 *       CAS wins (active->revoked), the rest update zero rows.</li>
 * </ul>
 *
 * <p>The partial-unique invariant (one ACTIVE row per (domain,user,type)) is a PG-only
 * partial index (skipped on H2 — see the changelog precondition); the at-most-one-active
 * invariant is enforced by the SERVICE on H2, exercised in {@link TubeAccessServiceTest}.
 * Here we prove the audit-retain + CAS + domain-scope semantics on the H2 slice store.
 */
@DataR2dbcTest
@Import({PostgresSliceTestConfig.class, TubeAccessRepository.class})
@ActiveProfiles("test")
class TubeAccessRepositoryTest extends PostgresTestSupport {

    @Autowired TubeAccessRepository repo;

    private static final AtomicInteger SEQ = new AtomicInteger();
    // Class-unique prefix: @DataR2dbcTest caches+shares ONE context (one H2 mem store)
    // across test classes with identical @Import config, so a bare per-class SEQ would
    // collide subjects with the service/guard slice tests. The "repo" tag keeps this
    // class's rows distinct in the shared store.
    private String user(String tag) { return "repo-" + tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void insertActiveUseGrant_roundTrips() {
            String u = user("us-grant");
            TubeAccess a = repo.insertActive(u, TubeAccess.TYPE_USE, null, "welcome", "admin-x", "brandx").block();
            assertThat(a.id()).isNotBlank();
            assertThat(a.isActive()).isTrue();
            assertThat(a.accessType()).isEqualTo(TubeAccess.TYPE_USE);
            assertThat(a.expiresAt()).isNull();           // permanent grant
            assertThat(a.domain()).isEqualTo("brandx");
            assertThat(a.grantedBySubject()).isEqualTo("admin-x");

            TubeAccess found = repo.findActive(u, TubeAccess.TYPE_USE, "brandx").block();
            assertThat(found).isNotNull();
            assertThat(found.id()).isEqualTo(a.id());
        }

        @Test
        void timedBan_carriesFutureExpiry() {
            String u = user("us-timeout");
            Instant exp = Instant.now().plusSeconds(3600);
            TubeAccess a = repo.insertActive(u, TubeAccess.TYPE_BANNED, exp, "cooldown", "admin-x", "brandx").block();
            assertThat(a.accessType()).isEqualTo(TubeAccess.TYPE_BANNED);
            assertThat(a.expiresAt()).isNotNull();
            assertThat(a.isEffectiveAt(Instant.now())).isTrue();              // in force now
            assertThat(a.isEffectiveAt(exp.plusSeconds(1))).isFalse();        // auto-restored after TTL
        }

        @Test
        void revoke_CASesActiveToRevoked_andRowIsRetainedAsAudit() {
            String u = user("us-revoke");
            TubeAccess a = repo.insertActive(u, TubeAccess.TYPE_BANNED, null, "bad", "admin-x", "brandx").block();

            assertThat(repo.revoke(a.id()).block()).isEqualTo(1L);   // CAS won
            // No longer active...
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").blockOptional()).isEmpty();
            // ...but the row is RETAINED (state=revoked, revoked_at stamped) = audit trail.
            List<TubeAccess> hist = repo.historyFor(u, "brandx").collectList().block();
            assertThat(hist).hasSize(1);
            assertThat(hist.get(0).state()).isEqualTo(TubeAccess.STATE_REVOKED);
            assertThat(hist.get(0).revokedAt()).isNotNull();
        }

        @Test
        void revoke_ofAlreadyRevoked_isNoOp() {
            String u = user("us-revoke2");
            TubeAccess a = repo.insertActive(u, TubeAccess.TYPE_USE, null, null, "admin-x", "brandx").block();
            assertThat(repo.revoke(a.id()).block()).isEqualTo(1L);
            assertThat(repo.revoke(a.id()).block()).isEqualTo(0L);  // already revoked — CAS matches nothing
        }
    }

    // ── CROSS-USER (DENY isolation + domain isolation) ────────────────────────
    @Nested
    class CrossUser {

        @Test
        void override_isInvisibleFromAnotherBrandScope() {
            String u = user("cu-iso");
            repo.insertActive(u, TubeAccess.TYPE_USE, null, null, "admin-x", "brandx").block();
            assertThat(repo.findActive(u, TubeAccess.TYPE_USE, "brandx").block()).isNotNull();
            // brandy's scope cannot see brandx's override.
            assertThat(repo.findActive(u, TubeAccess.TYPE_USE, "brandy").blockOptional()).isEmpty();
            assertThat(repo.activeFor(u, "brandy").collectList().block()).isEmpty();
        }

        @Test
        void sameUser_independentOverridesPerBrand() {
            String u = user("cu-perbrand");
            repo.insertActive(u, TubeAccess.TYPE_BANNED, null, "x-ban", "admin-x", "brandx").block();
            repo.insertActive(u, TubeAccess.TYPE_USE, null, "y-grant", "admin-y", "brandy").block();

            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandx").block()).isNotNull();
            assertThat(repo.findActive(u, TubeAccess.TYPE_BANNED, "brandy").blockOptional()).isEmpty();
            assertThat(repo.findActive(u, TubeAccess.TYPE_USE, "brandy").block()).isNotNull();
        }

        @Test
        void superadmin_nullDomain_seesEveryBrand() {
            String u = user("cu-su");
            repo.insertActive(u, TubeAccess.TYPE_USE, null, null, "admin-x", "su-bx").block();
            // The null-domain bypass resolves the override regardless of brand.
            TubeAccess got = repo.findActive(u, TubeAccess.TYPE_USE, null).block();
            assertThat(got).isNotNull();
            assertThat(got.domain()).isEqualTo("su-bx");
        }

        @Test
        void listActive_domainScoped_neverCrossesBrands() {
            String u = user("cu-list");
            repo.insertActive(u + "-x", TubeAccess.TYPE_USE, null, null, "a", "isl-bx").block();
            repo.insertActive(u + "-y", TubeAccess.TYPE_USE, null, null, "a", "isl-by").block();

            assertThat(repo.listActive("isl-bx").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo("isl-bx"));
            assertThat(repo.listActive("isl-by").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo("isl-by"));
        }
    }

    // ── CONCURRENT-CONFLICTING (CAS revoke) ───────────────────────────────────
    @Nested
    class ConcurrentConflicting {

        /** Many concurrent revokes of ONE active row: the CAS active->revoked serializes
         *  them — exactly ONE wins (rows-updated 1), the rest match zero rows. */
        @Test
        void concurrentRevokes_exactlyOneWins() {
            String u = user("cc-revoke");
            TubeAccess a = repo.insertActive(u, TubeAccess.TYPE_BANNED, null, null, "admin-x", "brandx").block();

            int racers = 20;
            Long winners = Flux.range(0, racers)
                    .flatMap(i -> repo.revoke(a.id()))
                    .reduce(0L, Long::sum)
                    .block(Duration.ofSeconds(30));

            assertThat(winners).isEqualTo(1L);   // exactly one CAS landed active->revoked
            assertThat(repo.historyFor(u, "brandx").collectList().block()).hasSize(1);  // one row, retained
        }
    }
}
