package systems.snapdragon.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.access.TubeAccessGuard;
import systems.snapdragon.tubebff.download.DownloadJob;
import systems.snapdragon.tubebff.download.DownloadJobRepository;
import systems.snapdragon.tubebff.download.DownloadJobService;
import systems.snapdragon.tubebff.download.StorageUsageR2dbcRepository;
import systems.snapdragon.tubebff.download.StorageUsageService;
import systems.snapdragon.tubebff.download.SubscriptionR2dbcRepository;
import systems.snapdragon.tubebff.download.SubscriptionRepository;
import systems.snapdragon.tubebff.download.TubeDownloadController;
import systems.snapdragon.tubebff.download.TubeDownloadDto;
import systems.snapdragon.tubebff.download.TubeDownloadWorkerController;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;
import systems.snapdragon.tubebff.support.TestDatabaseConfig;
import systems.snapdragon.tubebff.testsupport.TestIssuer;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RAW-API-DENY negative security suite for the tube download work-queue + the internal
 * worker seam — driven END-TO-END through THIS repo's REAL production
 * {@link SecurityConfig#filterChain} (the real {@code authorizeExchange} path/role table +
 * the real multi-issuer resource-server resolver, assembled by
 * {@link MultiIssuerControllerSliceSupport}), on REAL RS256 tokens minted by an in-process
 * {@link TestIssuer} (real JWKS, no live Casdoor, no network beyond loopback), against the
 * REAL Spring Data R2DBC repositories over a REAL H2 DB the production Liquibase changelog
 * ({@code 005-tube-download-queue}) is applied to. This is the MUTATION-RESISTANT
 * gold-exemplar shape (federation-api {@code CrossDomainWriteIsolationTest} /
 * {@code MultiIssuerSecuritySliceTest}): every DENY pairs the observable HTTP outcome
 * (401/403) with a DIRECT repository re-read proving the targeted DB row was NOT mutated.
 *
 * <p><b>Why this is additive coverage (not a duplicate).</b> The existing
 * {@code TubeDownloadWorkerControllerTest} is a {@code @WebFluxTest} that MOCKS
 * {@link DownloadJobService} — it proves the 403/401 status the gate returns, but it can
 * prove NOTHING about the EFFECT, because the service (and therefore every DB write) is
 * mocked away. This suite closes that gap: the worker seam's DENY is proven to leave the
 * queued job UNCLAIMED in the real DB, so a regression that opened {@code /bff/tube/internal/**}
 * to a human role — and thereby let them claim/complete another user's download — would
 * flip a re-read and FAIL here.
 *
 * <table>
 *   <caption>Negative cases (authority = SecurityConfig path table + DownloadJobService owner-derivation)</caption>
 *   <tr><th>Caller</th><th>Surface</th><th>Expect</th><th>Effect proof</th></tr>
 *   <tr><td>USER/MOD/ADMIN/SUPERADMIN</td>
 *       <td>POST /internal/download-jobs/claim+report</td><td>403</td>
 *       <td>seeded queued job still {@code queued}, no claimed_by; reported job unchanged</td></tr>
 *   <tr><td>no bearer</td><td>/internal</td><td>401</td><td>row untouched</td></tr>
 *   <tr><td>rogue-issuer / garbage / tampered bearer</td><td>/internal</td><td>401</td>
 *       <td>row untouched</td></tr>
 *   <tr><td>user B's token</td><td>GET /downloads (list)</td><td>200 owner-scoped</td>
 *       <td>NEVER surfaces user A's job (owner=jwt.sub server-derived)</td></tr>
 *   <tr><td>brand-Y token</td><td>GET /downloads (list)</td><td>200 brand-scoped</td>
 *       <td>NEVER surfaces a brand-X job</td></tr>
 * </table>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class,
        DownloadJobRepository.class, SubscriptionRepository.class})
class TubeRawApiDenyNegativeTest extends MultiIssuerControllerSliceSupport {

    @Autowired DownloadJobRepository jobRepo;
    @Autowired StorageUsageR2dbcRepository usageRepo;
    @Autowired SubscriptionR2dbcRepository subscriptionR2dbcRepository;

    /** Two trusted brands so the registry is genuinely multi-issuer (engages the resolver)
     *  + one untrusted "rogue" issuer for the forged-token fail-closed cases. */
    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;
    private WebTestClient client;

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String vid(String tag) { return "rawdeny-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        DomainRegistry registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        assertThat(registry.isMultiIssuer()).isTrue();
        assertThat(registry.isTrusted(rogue.issuerUri())).isFalse();

        // REAL service over the REAL H2/Liquibase repositories — the owner+domain are
        // server-derived from the validated JWT inside the service, never from a request field.
        StorageUsageService usage = new StorageUsageService(usageRepo, 10_737_418_240L);
        DownloadJobService service = new DownloadJobService(
                jobRepo, new SubscriptionRepository(subscriptionR2dbcRepository),
                usage, new PrincipalDomain(registry));

        // sliceClient(...) builds THIS repo's REAL SecurityConfig#filterChain wired to the
        // REAL multi-issuer resolver for `registry`, and registers ApiExceptionHandler so a
        // controller-body ApiException renders its mapped status/body. The worker seam's
        // 403/401 is produced by the filter chain BEFORE the controller.
        client = sliceClient(registry, new Object[]{new ApiExceptionHandler()},
                new TubeDownloadWorkerController(service),
                new TubeDownloadController(service, useGateAllowAll()));
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    /**
     * The download USER surface calls {@link TubeAccessGuard#assertCanUse} first. The
     * owner-scoping under test here is the SERVICE's server-derived (subject, domain), NOT
     * the use overlay (covered by {@code TubeMediaSecuritySliceTest} /
     * {@code TubeDownloadControllerTest}). So a grant is GIVEN via an allow-all stub guard,
     * and we then prove the owner/brand scope still isolates the queue: the IDOR proof
     * stands on the service's owner derivation, which the stub does not touch.
     */
    private static TubeAccessGuard useGateAllowAll() {
        return new TubeAccessGuard(null, null) {
            @Override
            public Mono<Void> assertCanUse(Authentication auth) {
                return Mono.empty();
            }
        };
    }

    // ── DB seed + re-read helpers (the verify-never-wrote primitives) ───────────

    /** Insert a fresh QUEUED job directly into the real DB and return its id. */
    private String seedQueuedJob(String subject, String videoId, String domain) {
        DownloadJob persisted = jobRepo.enqueue(subject, "chan", videoId, "Title", domain).block();
        assertThat(persisted).isNotNull();
        assertThat(persisted.state()).isEqualTo(DownloadJob.STATE_QUEUED);
        return persisted.id();
    }

    private DownloadJob reread(String id) {
        return jobRepo.findById(id).block();
    }

    private void assertStillQueuedUnclaimed(String id) {
        DownloadJob after = reread(id);
        assertThat(after).as("the seeded job must still exist").isNotNull();
        assertThat(after.state())
                .as("a denied worker call must NOT have claimed/completed the job")
                .isEqualTo(DownloadJob.STATE_QUEUED);
        assertThat(after.claimedBy())
                .as("a denied worker call must NOT stamp claimed_by")
                .isNull();
        assertThat(after.attempts())
                .as("a denied claim must NOT increment attempts")
                .isEqualTo(0);
    }

    private String claimBody(int limit) {
        return "{\"workerId\":\"worker-A\",\"limit\":" + limit + "}";
    }

    private String reportBody(String jobId) {
        return "{\"jobId\":\"" + jobId + "\",\"workerId\":\"worker-A\","
                + "\"result\":\"done\",\"bytes\":999,\"contentPath\":\"/x\"}";
    }

    private WebTestClient.ResponseSpec postClaimAs(String token, int limit) {
        return client.post().uri("/bff/tube/internal/download-jobs/claim")
                .headers(h -> { if (token != null) h.setBearerAuth(token); })
                .contentType(MediaType.APPLICATION_JSON).bodyValue(claimBody(limit))
                .exchange();
    }

    private WebTestClient.ResponseSpec postReportAs(String token, String jobId) {
        return client.post().uri("/bff/tube/internal/download-jobs/report")
                .headers(h -> { if (token != null) h.setBearerAuth(token); })
                .contentType(MediaType.APPLICATION_JSON).bodyValue(reportBody(jobId))
                .exchange();
    }

    // ════════════════════════════════════════════════════════════════════════════
    //  WORKER SEAM — ROLE_TUBE_WORKER ONLY: every human role DENIED + verify-never-wrote
    // ════════════════════════════════════════════════════════════════════════════

    /**
     * The load-bearing negative: the {@code /bff/tube/internal/**} claim seam is a MACHINE
     * operation. Each human role (USER/MOD/ADMIN/SUPERADMIN) is 403, AND the seeded queued
     * job in the real DB is still {@code queued} + unclaimed afterwards. A regression that
     * gave any human role a path to the worker seam would let them claim (and then complete)
     * another user's download job — the re-read would then show {@code claimed} and FAIL.
     */
    @Nested
    class WorkerSeamHumanRolesDeniedAndNeverWrote {

        @Test
        void plainTubeUser_claim_is403_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("user-claim"), "brandx");
            postClaimAs(brandX.mint("alice", List.of("tube")), 5)
                    .expectStatus().isForbidden();
            assertStillQueuedUnclaimed(id);
        }

        @Test
        void mod_claim_is403_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("mod-claim"), "brandx");
            postClaimAs(brandX.mint("mod-bob", List.of("mod", "tube")), 5)
                    .expectStatus().isForbidden();
            assertStillQueuedUnclaimed(id);
        }

        @Test
        void admin_claim_is403_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("admin-claim"), "brandx");
            postClaimAs(brandX.mint("admin-x", List.of("admin", "tube")), 5)
                    .expectStatus().isForbidden();
            assertStillQueuedUnclaimed(id);
        }

        /** SUPERADMIN too — the worker role is deliberately OUTSIDE the human hierarchy,
         *  so even the cross-domain super-role cannot claim another user's job. */
        @Test
        void superadmin_claim_is403_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("su-claim"), "brandx");
            postClaimAs(brandX.mint("root", List.of("superadmin", "admin", "tube")), 5)
                    .expectStatus().isForbidden();
            assertStillQueuedUnclaimed(id);
        }

        @Test
        void admin_report_is403_jobNeverCompleted() {
            String id = seedQueuedJob("alice", vid("admin-report"), "brandx");
            postReportAs(brandX.mint("admin-x", List.of("admin", "tube")), id)
                    .expectStatus().isForbidden();
            // A done-report would have stamped state=done + bytes + content_path; the gate
            // denied before the service ran, so the row is untouched.
            DownloadJob after = reread(id);
            assertThat(after.state()).isEqualTo(DownloadJob.STATE_QUEUED);
            assertThat(after.bytes()).isNull();
            assertThat(after.contentPath()).isNull();
        }

        @Test
        void superadmin_report_is403_jobNeverCompleted() {
            String id = seedQueuedJob("alice", vid("su-report"), "brandx");
            postReportAs(brandX.mint("root", List.of("superadmin")), id)
                    .expectStatus().isForbidden();
            assertThat(reread(id).state()).isEqualTo(DownloadJob.STATE_QUEUED);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    //  ANON + FORGED — 401 fail-closed + verify-never-wrote
    // ════════════════════════════════════════════════════════════════════════════

    @Nested
    class AnonAndForgedFailClosedAndNeverWrote {

        @Test
        void anon_claim_is401_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("anon-claim"), "brandx");
            postClaimAs(null, 5).expectStatus().isUnauthorized();
            assertStillQueuedUnclaimed(id);
        }

        @Test
        void anon_report_is401_jobNeverCompleted() {
            String id = seedQueuedJob("alice", vid("anon-report"), "brandx");
            postReportAs(null, id).expectStatus().isUnauthorized();
            assertThat(reread(id).state()).isEqualTo(DownloadJob.STATE_QUEUED);
        }

        /** A correctly-signed JWT whose ONLY sin is an unlisted (rogue) issuer — even
         *  loaded with tube_worker + superadmin roles, the per-issuer resolver returns NO
         *  authentication manager, so it 401s fail-closed BEFORE any authority is emitted,
         *  and the queued job is untouched. */
        @Test
        void rogueIssuerToken_claim_is401_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("rogue-claim"), "brandx");
            String token = rogue.mint("mallory", List.of("tube_worker", "superadmin"));
            postClaimAs(token, 5).expectStatus().isUnauthorized();
            assertStillQueuedUnclaimed(id);
        }

        @Test
        void garbageBearer_claim_is401_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("garbage-claim"), "brandx");
            client.post().uri("/bff/tube/internal/download-jobs/claim")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt")
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(claimBody(5))
                    .exchange().expectStatus().isUnauthorized();
            assertStillQueuedUnclaimed(id);
        }

        /** A brand-X token with a tampered signature (reversed) — must not validate. */
        @Test
        void tamperedSignature_claim_is401_jobNeverClaimed() {
            String id = seedQueuedJob("alice", vid("tamper-claim"), "brandx");
            String token = brandX.mint("mallory", List.of("tube_worker"));
            int lastDot = token.lastIndexOf('.');
            String tampered = token.substring(0, lastDot + 1)
                    + new StringBuilder(token.substring(lastDot + 1)).reverse();
            assertThat(tampered).isNotEqualTo(token);
            client.post().uri("/bff/tube/internal/download-jobs/claim")
                    .headers(h -> h.setBearerAuth(tampered))
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(claimBody(5))
                    .exchange().expectStatus().isUnauthorized();
            assertStillQueuedUnclaimed(id);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    //  OWNER-SCOPED IDOR + CROSS-TENANT — the user list surface is owner+brand scoped
    // ════════════════════════════════════════════════════════════════════════════

    @Nested
    class OwnerScopedListIsolation {

        /** A real authenticated brand-X user (bob) listing their OWN queue NEVER surfaces
         *  another user's (alice's) job in the same brand — the owner (user_subject) is
         *  server-derived from {@code jwt.getSubject()}, so there is no request field bob
         *  can set to read alice's queue (owner-scoped IDOR is structurally impossible). */
        @Test
        void userB_listOwnQueue_neverSeesUserAJob() {
            String aliceVid = vid("idor-alice");
            seedQueuedJob("alice", aliceVid, "brandx");
            String bobVid = vid("idor-bob");
            seedQueuedJob("bob", bobVid, "brandx");

            String bobToken = brandX.mint("bob", List.of("tube"));
            TubeDownloadDto.JobList list = client.get().uri("/bff/tube/downloads")
                    .headers(h -> h.setBearerAuth(bobToken))
                    .exchange().expectStatus().isOk()
                    .expectBody(TubeDownloadDto.JobList.class)
                    .returnResult().getResponseBody();

            assertThat(list).isNotNull();
            assertThat(list.jobs())
                    .as("bob's owner-scoped queue must NEVER surface alice's job")
                    .noneSatisfy(j -> assertThat(j.videoId()).isEqualTo(aliceVid));
            assertThat(list.jobs())
                    .as("bob DOES see his own job")
                    .anySatisfy(j -> {
                        assertThat(j.videoId()).isEqualTo(bobVid);
                        assertThat(j.userSubject()).isEqualTo("bob");
                    });
        }

        /** CROSS-TENANT: a brand-Y user with the SAME subject string ("alice") as a
         *  brand-X user NEVER sees the brand-X user's job — the domain is server-derived
         *  from the validated issuer, so the brand-Y read carries {@code AND domain='brandy'}
         *  and the brand-X row is invisible. Mutation-resistant: dropping the domain
         *  predicate would surface the brand-X job here and FAIL. */
        @Test
        void brandYUser_listOwnQueue_neverSeesBrandXJobOfSameSubject() {
            String xVid = vid("xtenant-x");
            seedQueuedJob("alice", xVid, "brandx");
            String yVid = vid("xtenant-y");
            seedQueuedJob("alice", yVid, "brandy");

            String brandYAlice = brandY.mint("alice", List.of("tube"));
            TubeDownloadDto.JobList list = client.get().uri("/bff/tube/downloads")
                    .headers(h -> h.setBearerAuth(brandYAlice))
                    .exchange().expectStatus().isOk()
                    .expectBody(TubeDownloadDto.JobList.class)
                    .returnResult().getResponseBody();

            assertThat(list).isNotNull();
            assertThat(list.jobs())
                    .as("a brand-Y 'alice' must NEVER see brand-X 'alice's job (domain-scoped)")
                    .noneSatisfy(j -> assertThat(j.videoId()).isEqualTo(xVid));
            assertThat(list.jobs())
                    .as("brand-Y alice sees her own brand-Y job")
                    .anySatisfy(j -> {
                        assertThat(j.videoId()).isEqualTo(yVid);
                        assertThat(j.domain()).isEqualTo("brandy");
                    });
        }
    }
}
