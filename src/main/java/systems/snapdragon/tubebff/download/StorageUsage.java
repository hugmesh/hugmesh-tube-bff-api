package systems.snapdragon.tubebff.download;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_storage_usage} row — the per-(domain, user_subject) running
 * content-byte accounting + the budget cap (schema in Liquibase
 * {@code db/changelog/005-tube-download-queue.xml}; PK(domain, user_subject)).
 *
 * <p>The download queue's PAUSE-ON-FULL guard reads this at enqueue/claim: a user whose
 * {@code usedBytes >= budgetBytes} is FULL, so new work is marked {@code skipped} rather
 * than spinning. {@code usedBytes} is bumped when a job completes (markDone adds the
 * downloaded byte count). {@code budgetBytes} is seeded from config on the first
 * accounting row and an ADMIN may raise/lower it.
 */
@Table("tube_storage_usage")
public record StorageUsage(
        @Id @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("used_bytes") long usedBytes,
        @Column("budget_bytes") long budgetBytes,
        @Column("updated_at") Instant updatedAt) {

    // tube_storage_usage has a COMPOSITE PK (domain, user_subject); Spring Data R2DBC
    // models only a single @Id, so {@code domain} carries the annotation purely to give
    // the mapping context an identifier property. This entity is NEVER persisted via
    // save()/findById() — its INSERT + the two arithmetic UPDATEs are explicit
    // constant-@Query writes and the read is a derived finder, so the single-@Id
    // limitation never affects correctness.

    /** True iff this user has reached/exceeded their budget — the pause-on-full predicate
     *  the enqueue/claim path applies (new work is skipped, never looped). */
    public boolean isFull() {
        return usedBytes >= budgetBytes;
    }

    /** Remaining headroom in bytes (never negative). */
    public long remainingBytes() {
        long rem = budgetBytes - usedBytes;
        return rem < 0 ? 0 : rem;
    }
}
