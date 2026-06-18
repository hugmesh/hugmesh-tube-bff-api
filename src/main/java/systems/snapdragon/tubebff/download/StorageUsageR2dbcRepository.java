package systems.snapdragon.tubebff.download;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@code tube_storage_usage} — the per-(domain,
 * user_subject) byte accounting + budget cap (schema in Liquibase
 * {@code db/changelog/005-tube-download-queue.xml}; COMPOSITE PK (domain, user_subject)).
 *
 * <p>The composite PK + arithmetic ({@code used_bytes = used_bytes + :delta}) UPDATEs +
 * the explicit-column INSERT cannot be expressed by {@code save()} (single-{@code @Id}
 * only) nor by derived methods, so the writes are constant-{@code @Query} statements
 * (per the data-access standard — the SQL is a {@code static final String}, never an
 * inline literal). The read is a derived finder pair (domain-scoped vs SUPERADMIN
 * un-pinned), matching the federation exemplar.
 */
public interface StorageUsageR2dbcRepository extends R2dbcRepository<StorageUsage, String> {

    String INSERT_DEFAULT =
            "INSERT INTO tube_storage_usage "
            + "(domain, user_subject, used_bytes, budget_bytes, updated_at) "
            + "VALUES (:dom, :user, 0, :budget, now())";

    @Modifying
    @Query(INSERT_DEFAULT)
    Mono<Long> insertDefault(@Param("dom") String dom, @Param("user") String user,
                             @Param("budget") long budget);

    String ADD_USAGE =
            "UPDATE tube_storage_usage SET used_bytes = used_bytes + :delta, "
            + "updated_at = now() WHERE domain = :dom AND user_subject = :user";

    @Modifying
    @Query(ADD_USAGE)
    Mono<Long> addUsage(@Param("delta") long delta, @Param("dom") String dom,
                        @Param("user") String user);

    String SET_BUDGET =
            "UPDATE tube_storage_usage SET budget_bytes = :budget, "
            + "updated_at = now() WHERE domain = :dom AND user_subject = :user";

    @Modifying
    @Query(SET_BUDGET)
    Mono<Long> setBudget(@Param("budget") long budget, @Param("dom") String dom,
                         @Param("user") String user);

    // ── read: WHERE user_subject [AND domain] -> first ──────────────────────────────
    Mono<StorageUsage> findFirstByUserSubject(String userSubject);

    Mono<StorageUsage> findFirstByUserSubjectAndDomain(String userSubject, String domain);
}
