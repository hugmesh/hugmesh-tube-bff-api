package systems.snapdragon.tubebff.access;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_access} row — the desired-state record of a per-principal
 * may-use OVERRIDE (schema in Liquibase {@code db/changelog/004-tube-access.xml}).
 * CLONED in shape from the owncast-bff {@code OwncastGrant}, swapping
 * {@code broadcast -> use}.
 *
 * <p>The overlay is the source of truth for the use grant / timeout / ban model.
 * Use is DEFAULT-DENY: the bare {@link systems.snapdragon.tubebff.access.TubeAccessController}
 * base role {@code ROLE_TUBE} is the gateway route/connect floor only and does NOT by
 * itself confer use — a {@link #TYPE_USE} grant is what lifts a user above the
 * default-deny floor:
 * <ul>
 *   <li>{@code accessType} — {@link #TYPE_USE} (a GRANT letting a USER use the tube
 *       service, which the bare ROLE_TUBE floor does not confer) or {@link #TYPE_BANNED}
 *       (a BAN/TIMEOUT denying use); CHECK-constrained in the DB.</li>
 *   <li>{@code state} — {@link #STATE_ACTIVE} while the override is in force; the
 *       service CASes it to {@link #STATE_REVOKED} on restore/revoke (the row is NEVER
 *       deleted — it is the audit trail).</li>
 *   <li>{@code expiresAt} — {@code null} means PERMANENT (a permanent grant, or a
 *       permanent ban); a FUTURE instant means a TIMEOUT that auto-restores when the
 *       clock passes WITHOUT a write ({@link #isEffectiveAt} treats {@code expiresAt <=
 *       now} as no-longer-active).</li>
 *   <li>{@code domain} — the brand/tenant the override belongs to, stamped SERVER-SIDE
 *       from the validated issuer. A scoped ADMIN acts only within their own brand;
 *       SUPERADMIN acts cross-domain.</li>
 * </ul>
 */
@Table("tube_access")
public record TubeAccess(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("access_type") String accessType,
        @Column("state") String state,
        @Column("granted_by_subject") String grantedBySubject,
        @Column("reason") String reason,
        @Column("created_at") Instant createdAt,
        @Column("expires_at") Instant expiresAt,
        @Column("revoked_at") Instant revokedAt) implements Persistable<String> {

    @Override
    public String getId() {
        return id;
    }

    /**
     * Always an INSERT. The store NEVER {@code save()}s a previously-read row — the
     * one mutation ({@code active -> revoked}) is a derived modifying CAS, not a
     * {@code save()} — so a {@code save()} call here is always a fresh app-generated-id
     * insert. (R2DBC otherwise decides insert-vs-update by {@code @Id} nullness, which
     * never works for an app-generated PK that is already populated.)
     */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    /** A GRANT of may-use to a principal who would not have it by the bare ROLE_TUBE
     *  floor (use is default-deny — ROLE_TUBE is the route/connect surface only, the
     *  grant is what lifts the user past default-deny). */
    public static final String TYPE_USE = "use";
    /** A BAN (or, with a future {@code expiresAt}, a TIMEOUT) denying use. */
    public static final String TYPE_BANNED = "banned";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A timed (non-permanent) override whose TTL has passed at {@code now} — an expired
     *  timeout. */
    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    /**
     * Is this override IN EFFECT at {@code now} — i.e. {@code state='active'} AND not
     * past its TTL. An active permanent row ({@code expiresAt} null) is always in effect;
     * an active timed row is in effect only until its {@code expiresAt}. This is the
     * single predicate the request-time enforcement guard applies, so an expired timeout
     * auto-restores (stops denying) WITHOUT a write.
     */
    public boolean isEffectiveAt(Instant now) {
        return isActive() && !isExpiredAt(now);
    }
}
