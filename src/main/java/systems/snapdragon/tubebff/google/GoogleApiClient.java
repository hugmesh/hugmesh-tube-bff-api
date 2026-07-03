package systems.snapdragon.tubebff.google;

import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The seam over Google's OAuth token endpoint + the YouTube Data API. An INTERFACE so
 * the services depend on a mockable boundary — the tests inject a fake to drive the
 * happy/refresh-failure paths WITHOUT a live Google (and without baking real creds into
 * CI). {@link DefaultGoogleApiClient} is the production WebClient impl.
 */
public interface GoogleApiClient {

    /** Exchange an authorization {@code code} (from the consent redirect) for tokens —
     *  the call that, given {@code access_type=offline&prompt=consent}, returns the
     *  long-lived REFRESH TOKEN plus the account's id/email. */
    Mono<TokenResponse> exchangeCode(String code);

    /** Mint a short-lived ACCESS token from the stored refresh token (the per-sync
     *  refresh). Errors when the refresh token was revoked/expired at Google — the
     *  signal the sync uses to set {@code reauth_required} and STOP. */
    Mono<String> refreshAccessToken(String refreshToken);

    /** Page {@code subscriptions.list?mine=true} with a user access token. {@code
     *  pageToken} is {@code null} for the first page; the returned page carries the next
     *  token (or {@code null} at the end). */
    Mono<SubscriptionsPage> listSubscriptions(String accessToken, String pageToken);

    /** Best-effort revoke of a token at Google's revocation endpoint (disconnect). */
    Mono<Void> revoke(String token);

    /** The relevant fields of Google's token-exchange response. The {@code refreshToken}
     *  is the crown jewel (present only with offline access + consent). */
    record TokenResponse(String refreshToken, String accessToken, String googleSub,
                         String googleEmail, String scopes) {}

    /** One subscribed channel (a {@code subscriptions.list} item, snippet-projected). */
    record Subscription(String channelId, String channelTitle, String thumbnailUrl) {}

    /** A page of subscriptions + the token for the NEXT page ({@code null} = last page). */
    record SubscriptionsPage(List<Subscription> items, String nextPageToken) {}
}
