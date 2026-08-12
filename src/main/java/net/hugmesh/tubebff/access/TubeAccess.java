package net.hugmesh.tubebff.access;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_access} row — the desired-state record of a per-principal
 * may-use override for the LocalTube service.
 *
 * <p>Schema: Liquibase {@code db/changelog/004-tube-access.xml}.
 * Modelled after the owncast-bff {@code OwncastGrant}, swapping {@code broadcast -> use}.
 *
 * <h2>Overlay model (DEFAULT-DENY)</h2>
 *
 * <p>Use is DEFAULT-DENY: the bare {@code ROLE_TUBE} is the gateway route/connect floor
 * only; it does NOT by itself allow use. A {@link #TYPE_USE} grant is the only mechanism
 * that lifts a user above the default-deny floor. The columns:
 *
 * <ul>
 *   <li>{@code accessType} — {@link #TYPE_USE} (grant) or {@link #TYPE_BANNED}
 *       (ban/timeout); CHECK-constrained in the DB.</li>
 *   <li>{@code state} — {@link #STATE_ACTIVE} while the override is in force; the service
 *       CASes it to {@link #STATE_REVOKED} on restore/revoke. Rows are NEVER hard-deleted
 *       — they are the audit trail.</li>
 *   <li>{@code expiresAt} — {@code null} = PERMANENT; a future instant = a TIMEOUT that
 *       auto-restores when the clock passes, without a write
 *       ({@link #isEffectiveAt} treats {@code expiresAt <= now} as inactive).</li>
 *   <li>{@code domain} — brand/tenant, stamped SERVER-SIDE from the validated JWT issuer.
 *       A scoped ADMIN governs only their own brand; SUPERADMIN is cross-domain.</li>
 * </ul>
 *
 * <h2>Precedence rule</h2>
 *
 * <pre>
 *   allowed  =  SUPERADMIN (exempt from ban — checked first, no DB read)
 *               OR ( active USE grant  AND  NOT active BAN/TIMEOUT )
 *   ban &gt; grant: an active ban denies a principal who also holds a grant
 * </pre>
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *   Caller           │ May READ overlay               │ May WRITE overlay
 *   ─────────────────┼────────────────────────────────┼───────────────────────────
 *   ROLE_USER / MOD  │ via TubeAccessGuard (enforce)  │ no
 *   ROLE_ADMIN       │ via TubeAccessGuard + listActive│ grant/timeout/ban/revoke
 *   ROLE_SUPERADMIN  │ all brands                     │ all brands (exempt from ban)
 * </pre>
 *
 * @see TubeAccessGuard
 * @see TubeAccessService
 * @see TubeAccessRepository
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

    /**
     * Returns {@code true} when {@code state = 'active'} — the override is in the active
     * lifecycle state (not yet revoked). Note: an active row may still be past its TTL;
     * use {@link #isEffectiveAt} to combine state AND expiry.
     *
     * @return {@code true} iff {@code state.equals(STATE_ACTIVE)}
     */
    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /**
     * Returns {@code true} when this is a TIMED override whose TTL has passed at
     * {@code now} — a timeout that has auto-expired without any write. A permanent
     * override ({@code expiresAt == null}) is never expired.
     *
     * @param now the instant to test against; typically {@code Instant.now()}
     * @return {@code true} iff {@code expiresAt != null && expiresAt <= now}
     */
    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    /**
     * Returns {@code true} iff this override is IN EFFECT at {@code now}: the state is
     * active AND the TTL has not yet passed. An active permanent row ({@code expiresAt ==
     * null}) is always in effect; an active timed row is in effect only until its
     * {@code expiresAt}. This is the single predicate {@link TubeAccessGuard} applies at
     * request time — an expired timeout auto-restores (stops denying) WITHOUT any write.
     *
     * @param now the instant to test; typically {@code Instant.now()}
     * @return {@code true} iff {@code isActive() && !isExpiredAt(now)}
     */
    public boolean isEffectiveAt(Instant now) {
        return isActive() && !isExpiredAt(now);
    }
}
