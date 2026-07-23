package systems.hugmesh.tubebff.download;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Per-(domain, user_subject) storage accounting and budget enforcement for the download
 * work-queue ({@code tube_storage_usage}; composite PK (domain, user_subject)).
 *
 * <p>This is the PAUSE-ON-FULL gate: at enqueue and at claim time the queue calls
 * {@link #isFull}; {@link #addUsage} increments {@code used_bytes} on completion; an
 * accounting row is created lazily on first access, seeded with the configured default
 * budget; an ADMIN may raise or lower the cap via {@link #setBudget}.
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link StorageUsageR2dbcRepository}
 * (derived read finders + constant-{@code @Query} INSERT/UPDATEs). Lazy-create-on-race,
 * no-op on non-positive delta, clamp-to-zero budget, and domain-scoping are unchanged.
 *
 * @see StorageUsageR2dbcRepository
 * @see StorageUsage
 * @see DownloadJobService
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
     * Returns the accounting row for (domain, user_subject), creating it lazily seeded
     * with {@link #defaultBudgetBytes()} if absent. The domain is defaulted to the platform
     * {@code default} domain when unscoped so the composite PK always carries a concrete
     * brand.
     *
     * @param userSubject the Casdoor subject of the owner
     * @param domain      the brand; blank/unscoped defaults to
     *                    {@link systems.hugmesh.commons.security.DomainRegistry#DEFAULT_DOMAIN}
     * @return a {@code Mono} emitting the existing or newly created {@link StorageUsage} row
     */
    public Mono<StorageUsage> ensure(String userSubject, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return find(userSubject, dom)
                .switchIfEmpty(Mono.defer(() -> insertDefault(userSubject, dom)));
    }

    /**
     * The pause-on-full predicate: returns {@code true} iff the user's used bytes have
     * reached or exceeded their budget. Lazily creates the accounting row if absent.
     *
     * @param userSubject the Casdoor subject of the owner
     * @param domain      the brand
     * @return a {@code Mono} emitting {@code true} when full, {@code false} otherwise;
     *         never errors (a missing row is lazily created)
     */
    public Mono<Boolean> isFull(String userSubject, String domain) {
        return ensure(userSubject, domain).map(StorageUsage::isFull);
    }

    /**
     * Add {@code deltaBytes} to the user's running used-bytes total. Called by
     * {@link DownloadJobService#report} after a successful {@code markDone} transition —
     * the only place {@code used_bytes} grows. Lazily ensures the accounting row. A
     * non-positive delta is a no-op that returns the current row unchanged.
     *
     * @param userSubject the Casdoor subject of the owner
     * @param domain      the brand
     * @param deltaBytes  the bytes to add; 0 or negative is a no-op
     * @return a {@code Mono} emitting the updated {@link StorageUsage} row (optimistic
     *         local projection — the DB row is authoritative after the UPDATE)
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
     * Set (raise or lower) the download budget cap for a user. Ensures the accounting row
     * exists first, then writes the new cap. A negative budget is clamped to 0, which
     * immediately makes the user full and pauses all further downloads.
     *
     * @param userSubject the Casdoor subject of the target user
     * @param domain      the brand (acting admin's brand, server-derived)
     * @param budgetBytes the new budget cap in bytes; negative is clamped to 0
     * @return a {@code Mono} emitting the updated {@link StorageUsage} row
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

    // Note: every caller (ensure/addUsage/setBudget) already normalizes domain to a concrete
    // brand (DomainRegistry.DEFAULT_DOMAIN or a real brand) before calling find(), so the
    // isUnscoped() arm below is unreachable in practice today. Unlike the sibling repositories
    // in access/ and download/ (TubeAccessRepository, DownloadJobRepository,
    // SubscriptionRepository), StorageUsage has no deliberate SUPERADMIN cross-domain read
    // path — this branch is kept only in case a future caller passes a raw, not-yet-normalized
    // domain straight through, matching the dispatch shape used elsewhere.
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
