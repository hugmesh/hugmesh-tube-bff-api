package systems.snapdragon.tubebff.download;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;
import java.time.OffsetDateTime;

/**
 * Per-(domain, user_subject) storage accounting + budget enforcement for the download
 * work-queue ({@code tube_storage_usage}; PK(domain, user_subject)). This is the
 * PAUSE-ON-FULL guard: at enqueue/claim the queue asks {@link #isFull} — a user whose
 * {@code used_bytes >= budget_bytes} has new work SKIPPED rather than spun on (the budget
 * check NEVER throws/loops). {@link #addUsage} bumps {@code used_bytes} when a job
 * completes (markDone). An accounting row is created lazily, seeded with the configured
 * default budget; an ADMIN may raise/lower it via {@link #setBudget}.
 *
 * <p>DOMAIN-scoped: every read/write carries the brand predicate, stamped SERVER-SIDE
 * from the validated issuer by the caller. The composite PK means exactly one accounting
 * row per (brand, user).
 */
@Service
public class StorageUsageService {

    private final DatabaseClient db;

    /** Default per-user budget (bytes) seeded onto a new accounting row. Configurable via
     *  {@code app.tube.default-budget-bytes}; defaults to 10 GiB. */
    private final long defaultBudgetBytes;

    public StorageUsageService(DatabaseClient db,
                               @Value("${app.tube.default-budget-bytes:10737418240}") long defaultBudgetBytes) {
        this.db = db;
        this.defaultBudgetBytes = defaultBudgetBytes;
    }

    public long defaultBudgetBytes() {
        return defaultBudgetBytes;
    }

    private static StorageUsage map(Row row, RowMetadata meta) {
        Long used = row.get("used_bytes", Long.class);
        Long budget = row.get("budget_bytes", Long.class);
        return new StorageUsage(
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                used == null ? 0L : used,
                budget == null ? 0L : budget,
                instant(row.get("updated_at", OffsetDateTime.class)));
    }

    /**
     * The accounting row for (domain, user_subject) — creating it lazily (seeded with the
     * default budget) if absent, so a caller always gets a concrete budget to compare
     * against. The {@code domain} is the owner's brand (defaulted to the platform
     * {@code default} domain when unscoped so the PK always carries a concrete brand).
     */
    public Mono<StorageUsage> ensure(String userSubject, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return find(userSubject, dom)
                .switchIfEmpty(Mono.defer(() -> insertDefault(userSubject, dom)));
    }

    /**
     * The pause-on-full predicate: true iff the user's used bytes have reached/exceeded
     * their budget. Lazily creates the accounting row (so a brand-new user starts NOT
     * full). NEVER throws — the queue simply marks new work 'skipped' when this is true.
     */
    public Mono<Boolean> isFull(String userSubject, String domain) {
        return ensure(userSubject, domain).map(StorageUsage::isFull);
    }

    /**
     * Add {@code deltaBytes} to the user's used total when a download completes (markDone).
     * Lazily ensures the accounting row first. A non-positive delta is a no-op read of the
     * current row (so an accidental double-call with 0/negative bytes never corrupts the
     * total).
     */
    public Mono<StorageUsage> addUsage(String userSubject, String domain, long deltaBytes) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return ensure(userSubject, dom)
                .flatMap(row -> {
                    if (deltaBytes <= 0) {
                        return Mono.just(row);
                    }
                    return db.sql("UPDATE tube_storage_usage SET used_bytes = used_bytes + :delta, "
                                    + "updated_at = now() WHERE domain = :dom AND user_subject = :user")
                            .bind("delta", deltaBytes).bind("dom", dom).bind("user", userSubject)
                            .fetch().rowsUpdated()
                            .thenReturn(new StorageUsage(dom, userSubject,
                                    row.usedBytes() + deltaBytes, row.budgetBytes(), Instant.now()));
                });
    }

    /**
     * Set (raise/lower) the user's budget cap — the ADMIN budget-management seam. Ensures
     * the accounting row exists, then writes the new cap. A negative budget is clamped to 0
     * (which makes the user immediately full = downloads paused).
     */
    public Mono<StorageUsage> setBudget(String userSubject, String domain, long budgetBytes) {
        long budget = budgetBytes < 0 ? 0 : budgetBytes;
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return ensure(userSubject, dom)
                .flatMap(row -> db.sql("UPDATE tube_storage_usage SET budget_bytes = :budget, "
                                + "updated_at = now() WHERE domain = :dom AND user_subject = :user")
                        .bind("budget", budget).bind("dom", dom).bind("user", userSubject)
                        .fetch().rowsUpdated()
                        .thenReturn(new StorageUsage(dom, userSubject,
                                row.usedBytes(), budget, Instant.now())));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private Mono<StorageUsage> find(String userSubject, String domain) {
        var spec = db.sql("SELECT domain, user_subject, used_bytes, budget_bytes, updated_at "
                        + "FROM tube_storage_usage WHERE user_subject = :user"
                        + DomainScope.andPredicate(domain))
                .bind("user", userSubject);
        return DomainScope.bind(spec, domain).map(StorageUsageService::map).first();
    }

    private Mono<StorageUsage> insertDefault(String userSubject, String dom) {
        return db.sql("INSERT INTO tube_storage_usage "
                        + "(domain, user_subject, used_bytes, budget_bytes, updated_at) "
                        + "VALUES (:dom, :user, 0, :budget, now())")
                .bind("dom", dom).bind("user", userSubject).bind("budget", defaultBudgetBytes)
                .fetch().rowsUpdated()
                .thenReturn(new StorageUsage(dom, userSubject, 0L, defaultBudgetBytes, Instant.now()))
                // A concurrent insert of the same PK loses the race — re-read the winner's row.
                .onErrorResume(e -> find(userSubject, dom));
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
