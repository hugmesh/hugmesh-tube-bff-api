package systems.hugmesh.tubebff.google;

import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The seam over Google's OAuth token endpoint + the YouTube Data API. An INTERFACE so
 * the services depend on a mockable boundary — the tests inject a fake to drive the
 * happy/refresh-failure paths WITHOUT a live Google (and without baking real creds into
 * CI). {@link DefaultGoogleApiClient} is the production WebClient impl.
 *
 * <h2>Caller-role matrix</h2>
 *
 * <pre>
 *   Method                  | Caller                 | Side-effect
 *   ------------------------+------------------------+-------------------------------------
 *   exchangeCode            | GoogleConnectService   | obtain refresh + access tokens
 *   refreshAccessToken      | SubscriptionsSyncService | mint short-lived access token
 *   listSubscriptions       | SubscriptionsSyncService | page YouTube subscriptions
 *   revoke                  | GoogleConnectService   | best-effort revoke at Google
 * </pre>
 *
 * @see DefaultGoogleApiClient
 * @see GoogleConnectService
 * @see SubscriptionsSyncService
 */
public interface GoogleApiClient {

    /**
     * Exchange an authorization {@code code} (received from Google's consent redirect)
     * for tokens. Given {@code access_type=offline&prompt=consent} the response includes a
     * long-lived REFRESH TOKEN plus the optional Google account sub/email.
     *
     * @param code the authorization code from Google's consent redirect
     * @return a {@code Mono} emitting the {@link TokenResponse}; errors on a non-2xx
     *         token response
     */
    Mono<TokenResponse> exchangeCode(String code);

    /**
     * Mint a short-lived access token from the stored refresh token. Used once per sync
     * cycle. Errors (emits a failed {@code Mono}) when the refresh token was
     * revoked or has expired at Google — the signal {@link SubscriptionsSyncService} uses
     * to mark {@code reauth_required} and stop without retrying.
     *
     * @param refreshToken the plaintext refresh token (decrypted in memory by the caller)
     * @return a {@code Mono} emitting the access token string; errors on non-2xx response
     */
    Mono<String> refreshAccessToken(String refreshToken);

    /**
     * Fetch one page of {@code subscriptions.list?mine=true} with a live access token.
     * {@code pageToken} is {@code null} for the first page; the returned
     * {@link SubscriptionsPage} carries the next-page token (or {@code null} at the last
     * page).
     *
     * @param accessToken the short-lived access token obtained from
     *                    {@link #refreshAccessToken}
     * @param pageToken   the page token from the previous page, or {@code null} for the
     *                    first page
     * @return a {@code Mono} emitting the page of subscriptions
     */
    Mono<SubscriptionsPage> listSubscriptions(String accessToken, String pageToken);

    /**
     * Best-effort revoke of a token at {@code https://oauth2.googleapis.com/revoke}. A
     * non-2xx response is swallowed (the token may already be invalid) so a disconnect
     * always proceeds to the soft-revoke step.
     *
     * @param token the refresh token (or access token) to revoke
     * @return a {@code Mono} that completes empty on success or after absorbing a revoke
     *         failure
     */
    Mono<Void> revoke(String token);

    /**
     * The relevant fields of Google's token-exchange response. The {@code refreshToken} is
     * the crown jewel — present only with {@code access_type=offline&prompt=consent}.
     */
    record TokenResponse(String refreshToken, String accessToken, String googleSub,
                         String googleEmail, String scopes) {}

    /** One subscribed channel from a {@code subscriptions.list} response, snippet-projected. */
    record Subscription(String channelId, String channelTitle, String thumbnailUrl) {}

    /**
     * A page of subscriptions and the token for the next page ({@code null} = last page).
     * Walk pages by passing {@code nextPageToken} back to {@link #listSubscriptions} until
     * it is {@code null}.
     */
    record SubscriptionsPage(List<Subscription> items, String nextPageToken) {}
}
