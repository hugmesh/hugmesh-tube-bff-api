package net.hugmesh.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_storage_usage} row — the per-(domain, user_subject) running
 * content-byte accounting plus the budget cap.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-download-queue.xml};
 * composite PK ({@code domain}, {@code user_subject}).
 *
 * <h2>Pause-on-full model</h2>
 *
 * <p>The download queue's PAUSE-ON-FULL guard reads this at enqueue and at claim time. A
 * user whose {@code usedBytes >= budgetBytes} is FULL: new work is recorded as
 * {@code skipped} rather than entering the active queue (no spin-loop, no throw). {@code
 * usedBytes} is incremented atomically when a job completes ({@link
 * StorageUsageService#addUsage} is the only site that grows it). {@code budgetBytes} is
 * seeded from config on the first row insert and an ADMIN may raise or lower it via
 * {@link StorageUsageService#setBudget}.
 *
 * <h2>R2DBC composite-PK note</h2>
 *
 * <p>Spring Data R2DBC models only a single {@code @Id}. The {@code domain} field carries
 * the annotation purely to provide a mapping-context identifier. This entity is NEVER
 * persisted via {@code save()} or looked up via {@code findById()} — all writes are
 * explicit constant-{@code @Query} operations and reads use derived finders, so the
 * single-{@code @Id} limitation never affects correctness.
 *
 * @see StorageUsageService
 * @see StorageUsageR2dbcRepository
 */
@Table("tube_storage_usage")
public record StorageUsage(
        @Id @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("used_bytes") long usedBytes,
        @Column("budget_bytes") long budgetBytes,
        @Column("updated_at") Instant updatedAt) {

    /**
     * Returns {@code true} when the user has reached or exceeded their budget cap —
     * the pause-on-full predicate the enqueue and claim paths apply. New work is
     * recorded as {@code skipped} rather than thrown or looped when this returns
     * {@code true}.
     *
     * @return {@code true} iff {@code usedBytes >= budgetBytes}
     */
    public boolean isFull() {
        return usedBytes >= budgetBytes;
    }

    /**
     * The remaining headroom in bytes before the budget is exhausted (never negative —
     * clamped to 0 when the user is already over budget).
     *
     * @return {@code max(0, budgetBytes - usedBytes)}
     */
    public long remainingBytes() {
        long rem = budgetBytes - usedBytes;
        return rem < 0 ? 0 : rem;
    }
}
