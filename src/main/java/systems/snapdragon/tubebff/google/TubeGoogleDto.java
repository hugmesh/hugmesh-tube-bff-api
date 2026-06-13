package systems.snapdragon.tubebff.google;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/tube/google-connect} + {@code /bff/tube/
 * subscriptions} HTTP boundary.
 *
 * <p><b>The refresh token NEVER crosses this boundary.</b> No DTO here carries the refresh
 * token, its ciphertext, the DEK, or any decrypted secret — the connect status exposes
 * only display-safe metadata ({@code googleEmail}, {@code connectedAt},
 * {@code reauthRequired}); the crown jewel stays server-side as AES-256-GCM ciphertext in
 * the DB.
 */
public final class TubeGoogleDto {

    private TubeGoogleDto() {}

    /** The consent URL the UI redirects the user to (no secrets — the signed state binds
     *  the principal). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AuthorizeUrl(String authorizeUrl) {}

    /** Display-safe status of a user's Google connection. Deliberately OMITS the refresh
     *  token / ciphertext / DEK. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConnectStatus(boolean connected, String googleEmail, String scopes,
                                Instant connectedAt, boolean reauthRequired) {
        public static ConnectStatus of(TubeGoogleLink link) {
            return new ConnectStatus(link.isLive(), link.googleEmail(), link.scopes(),
                    link.connectedAt(), link.reauthRequired());
        }
    }

    /** One subscribed channel as returned to the owner. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Subscription(String channelId, String channelTitle, String thumbnailUrl,
                               Instant syncedAt) {
        public static Subscription of(TubeSubscription s) {
            return new Subscription(s.channelId(), s.channelTitle(), s.thumbnailUrl(), s.syncedAt());
        }
    }

    /** The subscriptions list-response wrapper. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SubscriptionList(List<Subscription> subscriptions) {}

    /** The result of a sync — the count UPSERTed. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SyncResult(int synced) {}
}
