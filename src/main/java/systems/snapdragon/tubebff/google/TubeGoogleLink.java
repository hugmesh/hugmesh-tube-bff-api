package systems.snapdragon.tubebff.google;

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
public record TubeGoogleLink(
        String id,
        String domain,
        String userSubject,
        String googleSub,
        String googleEmail,
        String refreshTokenCiphertext,
        String dekId,
        String scopes,
        Instant connectedAt,
        boolean reauthRequired,
        Instant revokedAt) {

    /** The LIVE connection has not been soft-revoked. */
    public boolean isLive() {
        return revokedAt == null;
    }
}
