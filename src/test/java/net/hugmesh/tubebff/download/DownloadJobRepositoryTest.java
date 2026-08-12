package net.hugmesh.tubebff.download;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.tubebff.support.PostgresSliceTestConfig;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link DownloadJobRepository} against H2 (PostgreSQL-compat) with
 * the REAL Liquibase {@code 005-tube-download-queue} changelog. Delineated per the test
 * standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — enqueue creates a queued row; DEDUP: enqueuing the same
 *       video twice yields exactly ONE row; state transitions (claim -> downloading ->
 *       done/failed) CAS only with the owning worker.</li>
 *   <li><b>CONCURRENT-CONFLICTING</b> — many workers race to claim one batch: each job is
 *       claimed by EXACTLY ONE worker (no double-claim).</li>
 *   <li><b>CROSS-USER + DOMAIN ISOLATION</b> — listForOwner is owner+brand scoped; a job in
 *       brand X / for user A is invisible to brand Y / user B.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({PostgresSliceTestConfig.class, DownloadJobRepository.class})
@ActiveProfiles("test")
class DownloadJobRepositoryTest extends PostgresTestSupport {

    @Autowired DownloadJobRepository repo;

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "jobrepo-" + tag + "-" + SEQ.incrementAndGet(); }
    private String video(String tag) { return "vid-" + tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL + DEDUP ──────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void enqueue_createsQueuedRow() {
            String u = user("enq");
            String v = video("enq");
            DownloadJob j = repo.enqueue(u, "chan-1", v, "Title", "brandx").block();
            assertThat(j.id()).isNotBlank();
            assertThat(j.isQueued()).isTrue();
            assertThat(j.videoId()).isEqualTo(v);
            assertThat(j.domain()).isEqualTo("brandx");
            assertThat(j.attempts()).isZero();
        }

        /** DEDUP: the same video enqueued twice = exactly ONE row (idempotent on the
         *  (domain, user_subject, video_id) triple). */
        @Test
        void enqueue_sameVideoTwice_isOneRow() {
            String u = user("dedup");
            String v = video("dedup");
            DownloadJob first = repo.enqueue(u, "chan-1", v, "Title", "brandx").block();
            DownloadJob second = repo.enqueue(u, "chan-1", v, "Title again", "brandx").block();

            assertThat(second.id()).isEqualTo(first.id());   // same row returned, not a 2nd
            List<DownloadJob> all = repo.listForOwner(u, "brandx").collectList().block();
            assertThat(all).hasSize(1);
        }

        @Test
        void claimOne_thenDownloading_thenDone_transitionsWithOwningWorker() {
            String u = user("flow");
            String v = video("flow");
            DownloadJob j = repo.enqueue(u, "c", v, "T", "brandx").block();

            DownloadJob claimed = repo.claimOne(j.id(), "worker-A").block();
            assertThat(claimed).isNotNull();
            assertThat(claimed.state()).isEqualTo(DownloadJob.STATE_CLAIMED);
            assertThat(claimed.claimedBy()).isEqualTo("worker-A");
            assertThat(claimed.attempts()).isEqualTo(1);

            assertThat(repo.markDownloading(j.id(), "worker-A").block()).isEqualTo(1L);
            assertThat(repo.markDone(j.id(), "worker-A", 4096L, "/pvc/brandx/u/v.mp4").block()).isEqualTo(1L);

            DownloadJob done = repo.findById(j.id()).block();
            assertThat(done.state()).isEqualTo(DownloadJob.STATE_DONE);
            assertThat(done.bytes()).isEqualTo(4096L);
            assertThat(done.contentPath()).isEqualTo("/pvc/brandx/u/v.mp4");
        }

        /** A worker that does NOT own the claim cannot complete the job (the markDone CAS
         *  is guarded on claimed_by). */
        @Test
        void markDone_byNonOwningWorker_isNoOp() {
            String u = user("steal");
            String v = video("steal");
            DownloadJob j = repo.enqueue(u, "c", v, "T", "brandx").block();
            repo.claimOne(j.id(), "worker-A").block();

            assertThat(repo.markDone(j.id(), "worker-B", 1L, "/x").block()).isEqualTo(0L);  // not the claimer
            assertThat(repo.findById(j.id()).block().state()).isEqualTo(DownloadJob.STATE_CLAIMED);
        }

        @Test
        void claimOne_alreadyClaimed_isEmpty() {
            String u = user("twice");
            String v = video("twice");
            DownloadJob j = repo.enqueue(u, "c", v, "T", "brandx").block();
            assertThat(repo.claimOne(j.id(), "worker-A").block()).isNotNull();   // first wins
            assertThat(repo.claimOne(j.id(), "worker-B").blockOptional()).isEmpty(); // second sees no queued row
        }
    }

    // ── CONCURRENT-CONFLICTING (single-winner claim) ──────────────────────────
    @Nested
    class ConcurrentConflicting {

        /** Many workers race to claim ONE queued row via claimOne: exactly ONE wins (the
         *  guarded CAS serializes them), the rest get empty — no double-claim. */
        @Test
        void concurrentClaimOne_exactlyOneWorkerWins() {
            String u = user("cc-one");
            String v = video("cc-one");
            DownloadJob j = repo.enqueue(u, "c", v, "T", "brandx").block();

            int workers = 20;
            Set<String> winners = ConcurrentHashMap.newKeySet();
            Long wonCount = Flux.range(0, workers)
                    .flatMap(i -> repo.claimOne(j.id(), "worker-" + i)
                            .doOnNext(claimed -> winners.add(claimed.claimedBy()))
                            .map(c -> 1L)
                            .defaultIfEmpty(0L))
                    .reduce(0L, Long::sum)
                    .block(Duration.ofSeconds(30));

            assertThat(wonCount).isEqualTo(1L);     // exactly one CAS landed
            assertThat(winners).hasSize(1);         // claimed by exactly one worker
        }

        /** claimBatch over a pool of queued rows by two competing workers: every job is
         *  claimed by exactly one worker (no job claimed twice). The shared @DataR2dbcTest
         *  H2 store may hold unrelated queued rows from sibling tests, and claimBatch is a
         *  GLOBAL (cross-domain) oldest-first claim, so we assert against THIS test's own
         *  jobs (a stable owner+brand prefix) rather than the global claim count. */
        @Test
        void concurrentClaimBatch_noJobClaimedTwice() {
            String u = user("cc-batch");
            int jobs = 12;
            Set<String> mine = ConcurrentHashMap.newKeySet();
            for (int i = 0; i < jobs; i++) {
                mine.add(repo.enqueue(u, "c", video("cc-batch-" + i), "T" + i, "ccbatch").block().id());
            }
            // Two workers each try to claim a large pool concurrently (covers our 12 + any
            // sibling rows; enough budget to ensure all of ours get claimed by someone).
            List<DownloadJob> claimed = repo.claimBatch("worker-A", jobs * 8)
                    .mergeWith(repo.claimBatch("worker-B", jobs * 8))
                    .collectList().block(Duration.ofSeconds(30));

            // No id (ours or otherwise) appears twice -> no double-claim under concurrency.
            Set<String> seen = ConcurrentHashMap.newKeySet();
            for (DownloadJob job : claimed) {
                assertThat(seen.add(job.id())).as("job %s claimed twice", job.id()).isTrue();
            }
            // ...and every one of OUR 12 jobs ended up claimed by exactly one worker.
            List<DownloadJob> after = repo.listForOwner(u, "ccbatch").collectList().block();
            assertThat(after).hasSize(jobs);
            assertThat(after).allSatisfy(j ->
                    assertThat(j.state()).isEqualTo(DownloadJob.STATE_CLAIMED));
            assertThat(seen).containsAll(mine);
        }
    }

    // ── CROSS-USER + DOMAIN ISOLATION ─────────────────────────────────────────
    @Nested
    class Isolation {

        @Test
        void listForOwner_isOwnerScoped() {
            String a = user("own-a");
            String b = user("own-b");
            repo.enqueue(a, "c", video("a"), "A", "brandx").block();
            repo.enqueue(b, "c", video("b"), "B", "brandx").block();

            List<DownloadJob> aJobs = repo.listForOwner(a, "brandx").collectList().block();
            assertThat(aJobs).allSatisfy(j -> assertThat(j.userSubject()).isEqualTo(a));
            assertThat(repo.listForOwner(b, "brandx").collectList().block())
                    .allSatisfy(j -> assertThat(j.userSubject()).isEqualTo(b));
        }

        @Test
        void listForOwner_isDomainScoped() {
            String u = user("dom");
            repo.enqueue(u, "c", video("dom-x"), "X", "isoX").block();
            repo.enqueue(u, "c", video("dom-y"), "Y", "isoY").block();

            assertThat(repo.listForOwner(u, "isoX").collectList().block())
                    .allSatisfy(j -> assertThat(j.domain()).isEqualTo("isoX"));
            assertThat(repo.listForOwner(u, "isoY").collectList().block())
                    .allSatisfy(j -> assertThat(j.domain()).isEqualTo("isoY"));
        }

        /** The SAME video id for the SAME user in two DIFFERENT brands is two distinct jobs
         *  (dedup is per (domain, user, video), not global). */
        @Test
        void sameVideo_differentBrand_areDistinctJobs() {
            String u = user("dom-dedup");
            String v = video("dom-dedup");
            DownloadJob x = repo.enqueue(u, "c", v, "T", "ddX").block();
            DownloadJob y = repo.enqueue(u, "c", v, "T", "ddY").block();
            assertThat(x.id()).isNotEqualTo(y.id());
        }
    }
}
