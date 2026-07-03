package systems.snapdragon.tubebff.google;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/tube/google-connect} and
 * {@code /bff/tube/subscriptions} HTTP boundaries.
 *
 * <p>The refresh token NEVER crosses this boundary. No DTO here carries the refresh token,
 * its ciphertext, the DEK, or any decrypted secret — the connect status exposes only
 * display-safe metadata ({@code googleEmail}, {@code connectedAt}, {@code reauthRequired});
 * the crown jewel stays server-side as AES-256-GCM ciphertext in {@code tube_google_link}.
 *
 * <h2>Nested types</h2>
 *
 * <pre>
 *   AuthorizeUrl     — { "authorizeUrl": "..." }  (the Google consent URL)
 *   ConnectStatus    — display-safe connection status (connected/email/scopes/reauth)
 *   Subscription     — one subscribed channel (channelId/title/thumbnail/syncedAt)
 *   SubscriptionList — { "subscriptions": [...] }
 *   SyncResult       — { "synced": N }  (channels UPSERTed)
 * </pre>
 *
 * @see GoogleConnectController
 * @see TubeSubscriptionsController
 */
public final class TubeGoogleDto {

    private TubeGoogleDto() {}

    /**
     * The Google consent URL the UI redirects the user to. Contains no secrets — the
     * signed {@code state} query parameter binds the principal.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AuthorizeUrl(String authorizeUrl) {}

    /**
     * Display-safe status of a user's Google connection. Deliberately omits the refresh
     * token, its ciphertext, the DEK, and any other secret.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConnectStatus(boolean connected, String googleEmail, String scopes,
                                Instant connectedAt, boolean reauthRequired) {

        /**
         * Project a {@link TubeGoogleLink} to its display-safe wire shape.
         *
         * @param link the entity to project
         * @return a new {@code ConnectStatus}; {@code connected} reflects whether the link
         *         has not been soft-revoked
         */
        public static ConnectStatus of(TubeGoogleLink link) {
            return new ConnectStatus(link.isLive(), link.googleEmail(), link.scopes(),
                    link.connectedAt(), link.reauthRequired());
        }
    }

    /**
     * One subscribed channel as returned to the owner — the Google-sync view (title,
     * thumbnail, last synced timestamp).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Subscription(String channelId, String channelTitle, String thumbnailUrl,
                               Instant syncedAt) {

        /**
         * Project a {@link TubeSubscription} to its wire shape.
         *
         * @param s the entity to project
         * @return a new {@code Subscription}
         */
        public static Subscription of(TubeSubscription s) {
            return new Subscription(s.channelId(), s.channelTitle(), s.thumbnailUrl(), s.syncedAt());
        }
    }

    /** List-response wrapper for {@code GET /bff/tube/subscriptions}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SubscriptionList(List<Subscription> subscriptions) {}

    /** Sync result — the number of channels UPSERTed in this sync cycle. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SyncResult(int synced) {}
}
