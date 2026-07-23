package systems.hugmesh.tubebff.google;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_google_link} row — the per-(brand, user) Google OAuth connection
 * record for the YouTube subscriptions sync.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-google-link.xml}. The refresh token
 * lives ONLY as {@code refreshTokenCiphertext} (AES-256-GCM {@code base64(iv||ct||tag)}
 * from {@link TokenCipher}); this record NEVER carries the cleartext token, and neither
 * does any DTO crossing the HTTP boundary. {@code domain} and {@code userSubject} are
 * stamped server-side (a personal connect is always single-domain — no SUPERADMIN bypass).
 *
 * <p>The connection is never hard-deleted: a disconnect soft-revokes by stamping
 * {@code revoked_at}. The LIVE connection is the row where {@code revoked_at IS NULL}.
 *
 * <p>Implements {@link Persistable}&lt;String&gt; with {@code isNew = true} because the PK
 * is an app-generated UUID; {@code save()} is therefore always an INSERT.
 *
 * @see TubeGoogleLinkRepository
 * @see TubeGoogleLinkR2dbcRepository
 * @see TokenCipher
 */
@Table("tube_google_link")
public record TubeGoogleLink(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("google_sub") String googleSub,
        @Column("google_email") String googleEmail,
        @Column("refresh_token_ciphertext") String refreshTokenCiphertext,
        @Column("dek_id") String dekId,
        @Column("scopes") String scopes,
        @Column("connected_at") Instant connectedAt,
        @Column("reauth_required") boolean reauthRequired,
        @Column("revoked_at") Instant revokedAt) implements Persistable<String> {

    @Override
    public String getId() {
        return id;
    }

    /** Always an INSERT (DB-generated id, changelog 008). The soft-revoke + reauth-flag writes are
     *  constant-{@code @Query} partial UPDATEs, never a {@code save()} of a read row. */
    @Override
    @Transient
    public boolean isNew() {
        return true;
    }

    /**
     * Returns {@code true} when this connection is live — i.e. it has not been
     * soft-revoked ({@code revoked_at IS NULL}).
     *
     * @return {@code true} iff {@code revokedAt == null}
     */
    public boolean isLive() {
        return revokedAt == null;
    }
}
