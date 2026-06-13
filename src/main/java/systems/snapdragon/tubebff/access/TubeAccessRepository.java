package systems.snapdragon.tubebff.access;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.DomainScope;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_access} — the use grant/timeout/ban OVERLAY's
 * desired-state table (schema in Liquibase {@code db/changelog/004-tube-access.xml}).
 * CLONED from the owncast-bff {@code OwncastGrantRepository}: app-generated UUID ids
 * (portable across Postgres + the H2 test store), the reactive
 * {@code DatabaseClient.sql(...).bind().map().all()} shape, and the never-delete/
 * CAS-active->revoked audit semantics.
 *
 * <p>The service NEVER deletes a row — a restore/revoke is a CAS
 * {@code active -> revoked} ({@link #revoke}) so the table stays the audit trail.
 * {@link #insertActive} relies on the partial UNIQUE index
 * {@code (domain, user_subject, access_type) WHERE state='active'} so a concurrent
 * double-grant/ban surfaces as a unique-violation (PG) the service treats as
 * "already set"; on H2 the service's findActive-before-insert is the guard.
 *
 * <p>The READS are DOMAIN-scoped via {@link DomainScope}: a scoped admin only ever
 * resolves rows in THEIR brand; a {@code null} domain is the SUPERADMIN cross-domain
 * bypass (no predicate). The request-time enforcement read ({@link #activeFor}) is
 * scoped to the principal's own brand.
 */
@Repository
public class TubeAccessRepository {

    private final DatabaseClient db;

    public TubeAccessRepository(DatabaseClient db) {
        this.db = db;
    }

    private static final String COLS =
            "id, domain, user_subject, access_type, state, granted_by_subject, reason, "
            + "created_at, expires_at, revoked_at";

    private static TubeAccess map(Row row, RowMetadata meta) {
        return new TubeAccess(
                row.get("id", String.class),
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                row.get("access_type", String.class),
                row.get("state", String.class),
                row.get("granted_by_subject", String.class),
                row.get("reason", String.class),
                instant(row.get("created_at", OffsetDateTime.class)),
                instant(row.get("expires_at", OffsetDateTime.class)),
                instant(row.get("revoked_at", OffsetDateTime.class)));
    }

    // ── writes (insert active; CAS active->revoked) ────────────────────

    /**
     * Insert a new ACTIVE override (app-generated id) in the given brand and return it.
     * The caller is expected to have checked for an existing active row of the same type
     * first; the partial unique index is the backstop against a race. {@code expiresAt}
     * null = PERMANENT; a future instant = a TIMEOUT (a 'banned' row that auto-restores).
     * The {@code domain} is the acting principal's brand (defaulted to the platform
     * {@code default} domain for a SUPERADMIN unscoped write so a stamped row always
     * carries a concrete brand).
     */
    public Mono<TubeAccess> insertActive(String userSubject, String accessType, Instant expiresAt,
                                         String reason, String grantedBy, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        DatabaseClient.GenericExecuteSpec spec = db.sql(
                        "INSERT INTO tube_access "
                        + "(id, domain, user_subject, access_type, state, granted_by_subject, "
                        + " reason, created_at, expires_at, revoked_at) "
                        + "VALUES (:id, :dom, :user, :type, 'active', :by, :reason, now(), :exp, NULL)")
                .bind("id", id)
                .bind("dom", dom)
                .bind("user", userSubject)
                .bind("type", accessType)
                .bind("by", grantedBy);
        spec = (expiresAt == null)
                ? spec.bindNull("exp", OffsetDateTime.class)
                : spec.bind("exp", offset(expiresAt));
        spec = (reason == null)
                ? spec.bindNull("reason", String.class)
                : spec.bind("reason", reason);
        return spec.fetch().rowsUpdated()
                .thenReturn(new TubeAccess(id, dom, userSubject, accessType,
                        TubeAccess.STATE_ACTIVE, grantedBy, reason, Instant.now(), expiresAt, null));
    }

    /**
     * Compare-and-swap {@code active -> revoked} for one row id, stamping
     * {@code revoked_at}, guarded on the current state so only ONE writer wins the
     * transition (returns the rows-updated count: 1 = this caller won, 0 = already
     * revoked). The row is never deleted — the revoke is the audit of WHEN the override
     * was lifted.
     */
    public Mono<Long> revoke(String id) {
        return db.sql("UPDATE tube_access SET state = 'revoked', revoked_at = now() "
                        + "WHERE id = :id AND state = 'active'")
                .bind("id", id).fetch().rowsUpdated();
    }

    // ── reads (domain-scoped) ──────────────────────────────────────────

    /**
     * The active override of a given type for a (user) VISIBLE to the given tenant
     * scope. A scoped admin only ever resolves a row in THEIR brand (so it can never
     * clear / re-target another brand's override); SUPERADMIN ({@code null} domain)
     * resolves it in any brand. The predicate is added in-SQL so the row is invisible —
     * not merely hidden after the fact.
     */
    public Mono<TubeAccess> findActive(String userSubject, String accessType, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_access "
                        + "WHERE user_subject = :user AND access_type = :type AND state = 'active'"
                        + DomainScope.andPredicate(domain) + " ORDER BY created_at DESC, id")
                .bind("user", userSubject).bind("type", accessType);
        return DomainScope.bind(spec, domain).map(TubeAccessRepository::map).first();
    }

    /**
     * Every ACTIVE override for a principal WITHIN a brand — the request-time enforcement
     * working set ({@link TubeAccessGuard} reads this to apply the grant/ban precedence).
     * Scoped to the brand so a principal's overrides in brand X never affect brand Y. A
     * {@code null} domain is the SUPERADMIN cross-domain bypass (every brand's rows) —
     * but the guard never needs that path (SUPERADMIN is exempt from the overlay).
     */
    public Flux<TubeAccess> activeFor(String userSubject, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_access "
                        + "WHERE user_subject = :user AND state = 'active'"
                        + DomainScope.andPredicate(domain) + " ORDER BY access_type, created_at DESC")
                .bind("user", userSubject);
        return DomainScope.bind(spec, domain).map(TubeAccessRepository::map).all();
    }

    /** All ACTIVE overrides VISIBLE to the given tenant scope — the MANAGE read surface.
     *  A scoped admin sees ONLY their brand's rows; SUPERADMIN ({@code null} domain) sees
     *  every brand's. */
    public Flux<TubeAccess> listActive(String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_access WHERE state = 'active'"
                + DomainScope.andPredicate(domain) + " ORDER BY domain, user_subject, access_type")
                ;
        return DomainScope.bind(spec, domain).map(TubeAccessRepository::map).all();
    }

    /** The full history (active + revoked) for a principal WITHIN a brand — the audit
     *  read (state=revoked rows are RETAINED). A {@code null} domain is the SUPERADMIN
     *  cross-domain bypass. */
    public Flux<TubeAccess> historyFor(String userSubject, String domain) {
        var spec = db.sql("SELECT " + COLS + " FROM tube_access WHERE user_subject = :user"
                        + DomainScope.andPredicate(domain) + " ORDER BY created_at DESC, id")
                .bind("user", userSubject);
        return DomainScope.bind(spec, domain).map(TubeAccessRepository::map).all();
    }

    // ── timestamp helpers (R2DBC maps timestamptz <-> OffsetDateTime on H2/PG) ──
    private static OffsetDateTime offset(Instant i) {
        return i == null ? null : i.atOffset(ZoneOffset.UTC);
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
