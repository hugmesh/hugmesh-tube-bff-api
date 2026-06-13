package systems.snapdragon.tubebff.download;

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
public record StorageUsage(
        String domain,
        String userSubject,
        long usedBytes,
        long budgetBytes,
        Instant updatedAt) {

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
