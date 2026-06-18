package systems.snapdragon.tubebff.download;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;

/**
 * Per-(domain, user_subject) storage accounting + budget enforcement for the download
 * work-queue ({@code tube_storage_usage}; PK(domain, user_subject)). This is the
 * PAUSE-ON-FULL guard: at enqueue/claim the queue asks {@link #isFull}; {@link #addUsage}
 * bumps {@code used_bytes} on completion; an accounting row is created lazily, seeded with
 * the configured default budget; an ADMIN may raise/lower it via {@link #setBudget}.
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link StorageUsageR2dbcRepository}
 * (Spring Data R2DBC: derived read finders + constant-{@code @Query} INSERT/UPDATEs). The
 * lazy-create-on-race, the no-op non-positive delta, the clamp-to-zero budget, and the
 * domain-scoping are UNCHANGED.
 */
@Service
public class StorageUsageService {

    private final StorageUsageR2dbcRepository repo;

    /** Default per-user budget (bytes) seeded onto a new accounting row. Configurable via
     *  {@code app.tube.default-budget-bytes}; defaults to 10 GiB. */
    private final long defaultBudgetBytes;

    public StorageUsageService(StorageUsageR2dbcRepository repo,
                               @Value("${app.tube.default-budget-bytes:10737418240}") long defaultBudgetBytes) {
        this.repo = repo;
        this.defaultBudgetBytes = defaultBudgetBytes;
    }

    public long defaultBudgetBytes() {
        return defaultBudgetBytes;
    }

    /**
     * The accounting row for (domain, user_subject) — creating it lazily (seeded with the
     * default budget) if absent. The {@code domain} is the owner's brand (defaulted to the
     * platform {@code default} domain when unscoped so the PK always carries a concrete
     * brand).
     */
    public Mono<StorageUsage> ensure(String userSubject, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return find(userSubject, dom)
                .switchIfEmpty(Mono.defer(() -> insertDefault(userSubject, dom)));
    }

    /** The pause-on-full predicate: true iff used bytes have reached/exceeded the budget.
     *  Lazily creates the accounting row. NEVER throws. */
    public Mono<Boolean> isFull(String userSubject, String domain) {
        return ensure(userSubject, domain).map(StorageUsage::isFull);
    }

    /**
     * Add {@code deltaBytes} to the user's used total on completion (markDone). Lazily
     * ensures the row first. A non-positive delta is a no-op read of the current row.
     */
    public Mono<StorageUsage> addUsage(String userSubject, String domain, long deltaBytes) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return ensure(userSubject, dom)
                .flatMap(row -> {
                    if (deltaBytes <= 0) {
                        return Mono.just(row);
                    }
                    return repo.addUsage(deltaBytes, dom, userSubject)
                            .thenReturn(new StorageUsage(dom, userSubject,
                                    row.usedBytes() + deltaBytes, row.budgetBytes(), Instant.now()));
                });
    }

    /**
     * Set (raise/lower) the user's budget cap. Ensures the row exists, then writes the new
     * cap. A negative budget is clamped to 0 (user immediately full = downloads paused).
     */
    public Mono<StorageUsage> setBudget(String userSubject, String domain, long budgetBytes) {
        long budget = budgetBytes < 0 ? 0 : budgetBytes;
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return ensure(userSubject, dom)
                .flatMap(row -> repo.setBudget(budget, dom, userSubject)
                        .thenReturn(new StorageUsage(dom, userSubject,
                                row.usedBytes(), budget, Instant.now())));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private Mono<StorageUsage> find(String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserSubject(userSubject)
                : repo.findFirstByUserSubjectAndDomain(userSubject, domain);
    }

    private Mono<StorageUsage> insertDefault(String userSubject, String dom) {
        return repo.insertDefault(dom, userSubject, defaultBudgetBytes)
                .thenReturn(new StorageUsage(dom, userSubject, 0L, defaultBudgetBytes, Instant.now()))
                // A concurrent insert of the same PK loses the race — re-read the winner's row.
                .onErrorResume(e -> find(userSubject, dom));
    }
}
