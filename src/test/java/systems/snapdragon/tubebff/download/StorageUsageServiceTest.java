package systems.snapdragon.tubebff.download;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import systems.snapdragon.tubebff.support.TestDatabaseConfig;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice test for {@link StorageUsageService} (the pause-on-full budget guard) against H2
 * with the REAL Liquibase {@code tube_storage_usage} table. Delineated per the test
 * standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a fresh user is seeded with the default budget and is NOT
 *       full; addUsage grows used_bytes; reaching the budget flips isFull true
 *       (pause-on-full); setBudget raises/lowers the cap.</li>
 *   <li><b>NO-LOOP</b> — isFull is a single boolean read, never a throw/spin.</li>
 *   <li><b>DOMAIN ISOLATION</b> — usage/budget are per (domain, user_subject).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class StorageUsageServiceTest {

    @Autowired DatabaseClient db;

    /** Small default budget so the tests can fill it deterministically. */
    private static final long DEFAULT_BUDGET = 1000L;

    private StorageUsageService usage;

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "usage-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        usage = new StorageUsageService(db, DEFAULT_BUDGET);
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void freshUser_seededWithDefaultBudget_andNotFull() {
            String u = user("fresh");
            StorageUsage s = usage.ensure(u, "brandx").block();
            assertThat(s.usedBytes()).isZero();
            assertThat(s.budgetBytes()).isEqualTo(DEFAULT_BUDGET);
            assertThat(s.isFull()).isFalse();
            assertThat(usage.isFull(u, "brandx").block()).isFalse();
        }

        @Test
        void addUsage_growsUsedBytes() {
            String u = user("add");
            usage.addUsage(u, "brandx", 300L).block();
            StorageUsage s = usage.addUsage(u, "brandx", 200L).block();
            assertThat(s.usedBytes()).isEqualTo(500L);
            assertThat(s.isFull()).isFalse();   // 500 < 1000
        }

        /** Reaching the budget flips isFull true (pause-on-full) — the queue then skips new
         *  work rather than spinning. */
        @Test
        void reachingBudget_isFull_pauseOnFull() {
            String u = user("full");
            usage.addUsage(u, "brandx", DEFAULT_BUDGET).block();   // used == budget
            assertThat(usage.isFull(u, "brandx").block()).isTrue();
            // isFull is a plain boolean read repeated many times — never throws/loops.
            for (int i = 0; i < 5; i++) {
                assertThat(usage.isFull(u, "brandx").block()).isTrue();
            }
        }

        @Test
        void addUsage_nonPositiveDelta_isNoOp() {
            String u = user("zero");
            usage.addUsage(u, "brandx", 100L).block();
            StorageUsage s0 = usage.addUsage(u, "brandx", 0L).block();
            StorageUsage sNeg = usage.addUsage(u, "brandx", -50L).block();
            assertThat(s0.usedBytes()).isEqualTo(100L);
            assertThat(sNeg.usedBytes()).isEqualTo(100L);   // never corrupts the total
        }

        @Test
        void setBudget_raisesAndLowersCap() {
            String u = user("setbudget");
            usage.addUsage(u, "brandx", 800L).block();
            assertThat(usage.isFull(u, "brandx").block()).isFalse();   // 800 < 1000

            usage.setBudget(u, "brandx", 500L).block();                // lower below used
            assertThat(usage.isFull(u, "brandx").block()).isTrue();    // 800 >= 500 -> full

            StorageUsage raised = usage.setBudget(u, "brandx", 5000L).block();  // raise
            assertThat(raised.budgetBytes()).isEqualTo(5000L);
            assertThat(usage.isFull(u, "brandx").block()).isFalse();
        }

        @Test
        void setBudget_negative_clampsToZero_makesFull() {
            String u = user("negbudget");
            StorageUsage s = usage.setBudget(u, "brandx", -1L).block();
            assertThat(s.budgetBytes()).isZero();
            assertThat(usage.isFull(u, "brandx").block()).isTrue();   // 0 used >= 0 budget
        }
    }

    // ── DOMAIN ISOLATION ──────────────────────────────────────────────────────
    @Nested
    class DomainIsolation {

        /** Usage/budget are per (domain, user): filling brand X does not make brand Y full
         *  for the same subject. */
        @Test
        void usageIsPerBrand() {
            String u = user("perbrand");
            usage.addUsage(u, "brX", DEFAULT_BUDGET).block();   // fill brandX

            assertThat(usage.isFull(u, "brX").block()).isTrue();
            assertThat(usage.isFull(u, "brY").block()).isFalse();   // brandY untouched
        }
    }
}
