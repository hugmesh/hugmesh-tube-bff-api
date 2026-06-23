package systems.snapdragon.tubebff.download;

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
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;
import org.springframework.test.context.ActiveProfiles;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.tubebff.support.PostgresSliceTestConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The download-queue orchestration ({@link DownloadJobService}) over the REAL repos + a
 * multi-brand {@link PrincipalDomain}, so the SERVER-SIDE owner + domain derivation is
 * exercised end to end. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — enqueueFromSubscriptions turns the owner's subscriptions
 *       into queued jobs (DEDUPED: re-running adds no rows); a report(done) adds the bytes
 *       to the owner's storage usage.</li>
 *   <li><b>PAUSE-ON-FULL</b> — when the owner's budget is full, enqueue records 'skipped'
 *       (never queued, never a throw-loop); a claim of an over-budget owner's job is
 *       dropped (re-marked failed/skipped, not handed to the worker).</li>
 *   <li><b>CROSS-USER (DENY isolation)</b> — A cannot list/enqueue B's jobs (owner is
 *       server-derived, not a request field); DOMAIN isolation per brand.</li>
 *   <li><b>FAIL-CLOSED</b> — a non-JWT / subject-less principal is rejected (no forge-able
 *       owner).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({PostgresSliceTestConfig.class, DownloadJobRepository.class, SubscriptionRepository.class})
@ActiveProfiles("test")
class DownloadJobServiceTest extends PostgresTestSupport {

    @Autowired DownloadJobRepository jobs;
    @Autowired SubscriptionRepository subs;
    @Autowired StorageUsageR2dbcRepository usageRepo;

    private static final long DEFAULT_BUDGET = 1000L;

    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final PrincipalDomain PD = new PrincipalDomain(MULTI);

    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private StorageUsageService usage;
    private DownloadJobService service;

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "svcjob-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        usage = new StorageUsageService(usageRepo, DEFAULT_BUDGET);
        service = new DownloadJobService(jobs, subs, usage, PD);
    }

    /** A JWT-principal Authentication for a brand (issuer) + subject + roles. */
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

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void enqueueFromSubscriptions_createsQueuedJobsPerSubscription() {
            String u = user("enq");
            Authentication user = principal(ISS_X, u, "tube");
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "brandx").block();
            subs.upsert(u, "chan-2", "Chan Two", "vidB", "Video B", "brandx").block();

            List<DownloadJob> created = service.enqueueFromSubscriptions(user).collectList().block();
            assertThat(created).hasSize(2);
            assertThat(created).allSatisfy(j -> {
                assertThat(j.userSubject()).isEqualTo(u);
                assertThat(j.domain()).isEqualTo("brandx");
                assertThat(j.isQueued()).isTrue();
            });
        }

        /** DEDUP: re-running enqueue adds NO new rows (idempotent on video id). */
        @Test
        void enqueueFromSubscriptions_isIdempotent() {
            String u = user("idem");
            Authentication user = principal(ISS_X, u, "tube");
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "brandx").block();

            service.enqueueFromSubscriptions(user).collectList().block();
            service.enqueueFromSubscriptions(user).collectList().block();   // again
            assertThat(jobs.listForOwner(u, "brandx").collectList().block()).hasSize(1);
        }

        /** A subscription with no known latest video is skipped (nothing to download yet). */
        @Test
        void enqueueFromSubscriptions_skipsSubsWithNoVideo() {
            String u = user("novideo");
            Authentication user = principal(ISS_X, u, "tube");
            subs.upsert(u, "chan-1", "Chan One", null, null, "brandx").block();

            assertThat(service.enqueueFromSubscriptions(user).collectList().block()).isEmpty();
            assertThat(jobs.listForOwner(u, "brandx").collectList().block()).isEmpty();
        }

        /** report(done) marks the job done AND adds its bytes to the owner's storage usage
         *  (the only place used_bytes grows). */
        @Test
        void reportDone_addsUsageToOwner() {
            String u = user("done");
            Authentication user = principal(ISS_X, u, "tube");
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "brandx").block();
            service.enqueueFromSubscriptions(user).collectList().block();

            // Claim THIS user's own job directly (the service-level claim is a global
            // oldest-first scan, which the shared store makes non-deterministic).
            DownloadJob mine = jobs.listForOwner(u, "brandx").blockFirst();
            jobs.claimOne(mine.id(), "worker-A").block();

            DownloadJob done = service.report(mine.id(), "worker-A",
                    DownloadJob.STATE_DONE, 256L, "/pvc/brandx/" + u + "/vidA.mp4", null).block();
            assertThat(done.state()).isEqualTo(DownloadJob.STATE_DONE);
            assertThat(done.bytes()).isEqualTo(256L);

            assertThat(usage.ensure(u, "brandx").block().usedBytes()).isEqualTo(256L);
        }

        /** report(failed) stamps the error and does NOT grow usage. */
        @Test
        void reportFailed_stampsError_noUsage() {
            String u = user("fail");
            Authentication user = principal(ISS_X, u, "tube");
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "brandx").block();
            service.enqueueFromSubscriptions(user).collectList().block();

            DownloadJob mine = jobs.listForOwner(u, "brandx").blockFirst();
            jobs.claimOne(mine.id(), "worker-A").block();

            DownloadJob failed = service.report(mine.id(), "worker-A",
                    DownloadJob.STATE_FAILED, 0L, null, "yt-dlp exited 1").block();
            assertThat(failed.state()).isEqualTo(DownloadJob.STATE_FAILED);
            assertThat(failed.lastError()).isEqualTo("yt-dlp exited 1");
            assertThat(usage.ensure(u, "brandx").block().usedBytes()).isZero();
        }
    }

    // ── PAUSE-ON-FULL ─────────────────────────────────────────────────────────
    @Nested
    class PauseOnFull {

        /** When the owner is over budget, enqueue records the job as 'skipped' (not queued)
         *  — pause-on-full, never a throw-loop. */
        @Test
        void enqueue_whenBudgetFull_marksSkipped() {
            String u = user("pof-enq");
            Authentication user = principal(ISS_X, u, "tube");
            usage.addUsage(u, "brandx", DEFAULT_BUDGET).block();   // fill the budget
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "brandx").block();

            List<DownloadJob> created = service.enqueueFromSubscriptions(user).collectList().block();
            assertThat(created).hasSize(1);
            assertThat(created.get(0).state()).isEqualTo(DownloadJob.STATE_SKIPPED);
        }

        /** A claim of an over-budget owner's still-queued job is DROPPED (not handed to the
         *  worker) — pause-on-full at claim time. (The shared store may hold sibling tests'
         *  queued rows and claim is a GLOBAL oldest-first claim, so we assert about THIS
         *  user's job specifically: it is never in the worker's batch, and it is left in a
         *  non-downloadable state.) */
        @Test
        void claim_whenOwnerBudgetFull_dropsTheJob() {
            String u = user("pof-claim");
            Authentication user = principal(ISS_X, u, "pofclaim");
            // Enqueue while NOT full...
            subs.upsert(u, "chan-1", "Chan One", "vidA", "Video A", "pofclaim").block();
            service.enqueueFromSubscriptions(user).collectList().block();
            // ...then the owner goes over budget before the worker claims.
            usage.addUsage(u, "pofclaim", DEFAULT_BUDGET).block();

            List<DownloadJob> claimed = service.claim("worker-A", 50).collectList().block();
            // OUR over-budget user's job is never handed to the worker (paused).
            assertThat(claimed).noneSatisfy(j -> assertThat(j.userSubject()).isEqualTo(u));
            // ...and it was dropped to a non-downloadable state (failed = skipped-for-budget).
            assertThat(jobs.listForOwner(u, "pofclaim").collectList().block())
                    .allSatisfy(j -> assertThat(j.state()).isEqualTo(DownloadJob.STATE_FAILED));
        }
    }

    // ── CROSS-USER (DENY isolation) + DOMAIN isolation ────────────────────────
    @Nested
    class Isolation {

        /** A cannot list B's jobs — the owner is server-derived from the JWT, never a
         *  request field. */
        @Test
        void userA_cannotListUserBsJobs() {
            String a = user("iso-a");
            String b = user("iso-b");
            subs.upsert(b, "chan-1", "Chan", "vidB", "VB", "brandx").block();
            service.enqueueFromSubscriptions(principal(ISS_X, b, "tube")).collectList().block();

            // A lists — sees none of B's jobs.
            List<DownloadJob> aSees = service.listForOwner(principal(ISS_X, a, "tube")).collectList().block();
            assertThat(aSees).noneSatisfy(j -> assertThat(j.userSubject()).isEqualTo(b));
        }

        /** A's enqueue only ever creates A's own jobs (B's subscriptions are invisible to A's
         *  server-derived owner). */
        @Test
        void enqueue_onlyEnqueuesCallersOwnSubscriptions() {
            String a = user("iso-enq-a");
            String b = user("iso-enq-b");
            subs.upsert(b, "chan-1", "Chan", "vidB", "VB", "brandx").block();   // only B has a sub

            // A enqueues — A has no subs, so nothing is created (and B's sub is untouched).
            assertThat(service.enqueueFromSubscriptions(principal(ISS_X, a, "tube"))
                    .collectList().block()).isEmpty();
            assertThat(jobs.listForOwner(b, "brandx").collectList().block()).isEmpty();
        }

        /** The same subject in brand Y sees none of brand X's jobs (domain isolation; owner
         *  domain is issuer-derived). */
        @Test
        void domainIsolation_sameSubjectDifferentBrand() {
            String u = user("iso-dom");
            subs.upsert(u, "chan-1", "Chan", "vidA", "VA", "brandx").block();
            service.enqueueFromSubscriptions(principal(ISS_X, u, "tube")).collectList().block();

            // Same subject authenticating in brand Y sees no jobs (brandY queue is empty).
            assertThat(service.listForOwner(principal(ISS_Y, u, "tube")).collectList().block()).isEmpty();
        }
    }

    // ── FAIL-CLOSED owner derivation ──────────────────────────────────────────
    @Nested
    class FailClosed {

        /** A non-JWT principal has no usable owner subject — rejected (no anonymous /
         *  forge-able owner). */
        @Test
        void nonJwtPrincipal_isRejected() {
            Authentication notJwt = new UsernamePasswordAuthenticationToken(
                    "plain-name", "n/a", List.of(new SimpleGrantedAuthority("ROLE_TUBE")));
            assertThatThrownBy(() -> service.listForOwner(notJwt).collectList().block())
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}
