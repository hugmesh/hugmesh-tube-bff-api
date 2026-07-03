package systems.snapdragon.tubebff.google;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single {@code tube_google_link} row — the per-(brand,user) Google OAuth connection
 * (schema in Liquibase {@code db/changelog/005-tube-google-link.xml}).
 *
 * <p>The refresh token lives ONLY as {@code refreshTokenCiphertext} (AES-256-GCM
 * {@code base64(iv||ct||tag)} from {@link TokenCipher}); this record NEVER carries the
 * cleartext token, and neither does any DTO crossing the HTTP boundary. {@code domain} +
 * {@code userSubject} are stamped server-side (a personal connect is single-domain).
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

    /** The LIVE connection has not been soft-revoked. */
    public boolean isLive() {
        return revokedAt == null;
    }
}
