package systems.hugmesh.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for the {@code tube_storage_usage} per-user byte accounting
 * and budget cap table.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-download-queue.xml};
 * composite PK ({@code domain}, {@code user_subject}).
 *
 * <p>The composite PK, the arithmetic UPDATE ({@code used_bytes = used_bytes + :delta}), and
 * the explicit-column INSERT cannot be expressed by {@code save()} (single-{@code @Id} only)
 * nor by derived methods, so all three writes are constant-{@code @Query} strings (per the
 * data-access standard — SQL as a {@code static final String}, never an inline literal). The
 * read is a derived finder pair (domain-scoped vs SUPERADMIN un-pinned), matching the
 * federation exemplar.
 *
 * @see StorageUsageService
 * @see StorageUsage
 */
public interface StorageUsageR2dbcRepository extends R2dbcRepository<StorageUsage, String> {

    String INSERT_DEFAULT =
            "INSERT INTO tube_storage_usage "
            + "(domain, user_subject, used_bytes, budget_bytes, updated_at) "
            + "VALUES (:dom, :user, 0, :budget, now())";

    /**
     * Insert a fresh accounting row with {@code used_bytes = 0} and the given budget cap.
     * Called lazily by {@link StorageUsageService#ensure} on the first access; a concurrent
     * insert of the same composite PK is handled by the caller via {@code onErrorResume}.
     *
     * @param dom    the brand (never null/blank — already defaulted by the service layer)
     * @param user   the Casdoor subject of the owner
     * @param budget the initial budget cap in bytes
     * @return a {@code Mono} emitting the rows-inserted count (1 on success)
     */
    @Modifying
    @Query(INSERT_DEFAULT)
    Mono<Long> insertDefault(@Param("dom") String dom, @Param("user") String user,
                             @Param("budget") long budget);

    String ADD_USAGE =
            "UPDATE tube_storage_usage SET used_bytes = used_bytes + :delta, "
            + "updated_at = now() WHERE domain = :dom AND user_subject = :user";

    /**
     * Atomically increment {@code used_bytes} by {@code delta} for a specific user+brand.
     * This is the only write path that grows the byte count; called by
     * {@link StorageUsageService#addUsage} after a successful {@code markDone} transition.
     *
     * @param delta the number of bytes to add (must be positive; the service guards this)
     * @param dom   the brand
     * @param user  the Casdoor subject of the owner
     * @return a {@code Mono} emitting the rows-updated count (1 on success)
     */
    @Modifying
    @Query(ADD_USAGE)
    Mono<Long> addUsage(@Param("delta") long delta, @Param("dom") String dom,
                        @Param("user") String user);

    String SET_BUDGET =
            "UPDATE tube_storage_usage SET budget_bytes = :budget, "
            + "updated_at = now() WHERE domain = :dom AND user_subject = :user";

    /**
     * Replace the budget cap for a user+brand with {@code budget}. The caller is
     * responsible for clamping a negative value to 0 before this is invoked.
     *
     * @param budget the new budget cap in bytes
     * @param dom    the brand
     * @param user   the Casdoor subject of the owner
     * @return a {@code Mono} emitting the rows-updated count (1 on success)
     */
    @Modifying
    @Query(SET_BUDGET)
    Mono<Long> setBudget(@Param("budget") long budget, @Param("dom") String dom,
                         @Param("user") String user);

    // ── read: WHERE user_subject [AND domain] -> first ──────────────────────────────
    Mono<StorageUsage> findFirstByUserSubject(String userSubject);

    Mono<StorageUsage> findFirstByUserSubjectAndDomain(String userSubject, String domain);
}
