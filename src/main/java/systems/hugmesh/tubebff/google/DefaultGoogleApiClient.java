package systems.hugmesh.tubebff.google;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Production {@link GoogleApiClient} backed by a reactive {@link WebClient}. Calls:
 * <ul>
 *   <li>{@code https://oauth2.googleapis.com/token} — authorization-code exchange and the
 *       refresh-token grant;</li>
 *   <li>{@code https://www.googleapis.com/youtube/v3/subscriptions?mine=true&part=snippet}
 *       — subscribed-channel listing (paged, max 50 results);</li>
 *   <li>{@code https://oauth2.googleapis.com/revoke} — best-effort token revocation.</li>
 * </ul>
 *
 * <p>The dedicated Google OAuth Web client id/secret and redirect URI come from
 * {@link TubeGoogleProperties} (Vault {@code secret/<brand>/tube-google} → ESO). A
 * non-2xx from the token endpoint (e.g. {@code invalid_grant} when the refresh token was
 * revoked externally) surfaces as a failed {@code Mono} so {@link SubscriptionsSyncService}
 * marks {@code reauth_required} and stops without retrying.
 *
 * @see GoogleApiClient
 * @see TubeGoogleProperties
 */
@Component
public class DefaultGoogleApiClient implements GoogleApiClient {

    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final String REVOKE_URI = "https://oauth2.googleapis.com/revoke";
    private static final String SUBSCRIPTIONS_URI =
            "https://www.googleapis.com/youtube/v3/subscriptions";

    private final WebClient web;
    private final TubeGoogleProperties props;

    public DefaultGoogleApiClient(WebClient tubeGoogleWebClient, TubeGoogleProperties props) {
        this.web = tubeGoogleWebClient;
        this.props = props;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Posts to {@value #TOKEN_URI} with {@code grant_type=authorization_code}. A
     * non-2xx response (e.g. {@code invalid_grant}) is mapped to a {@code badGateway}
     * {@link systems.hugmesh.commons.web.ApiException}.
     */
    @Override
    public Mono<TokenResponse> exchangeCode(String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("redirect_uri", props.getRedirectUri());
        form.add("grant_type", "authorization_code");
        return web.post().uri(TOKEN_URI)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .onStatus(HttpStatusCode::isError, r -> Mono.error(
                        ApiException.badGateway("google token exchange failed")))
                .bodyToMono(Map.class)
                .map(this::toTokenResponse);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Posts to {@value #TOKEN_URI} with {@code grant_type=refresh_token}. A 4xx response
     * (e.g. {@code invalid_grant} — the user revoked access) surfaces as a failed
     * {@code Mono} so the caller can flag {@code reauth_required}.
     */
    @Override
    public Mono<String> refreshAccessToken(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("refresh_token", refreshToken);
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("grant_type", "refresh_token");
        return web.post().uri(TOKEN_URI)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                // A revoked/expired refresh token returns 4xx (invalid_grant) — surface as
                // an error so the sync sets reauth_required + stops (no retry loop).
                .onStatus(HttpStatusCode::isError, r -> Mono.error(
                        ApiException.badGateway("google refresh failed")))
                .bodyToMono(Map.class)
                .map(m -> str(m, "access_token"));
    }

    /**
     * {@inheritDoc}
     *
     * <p>GETs {@value #SUBSCRIPTIONS_URI} with {@code part=snippet&mine=true&maxResults=50}.
     * Appends {@code pageToken} when non-blank. The access token is passed as a
     * {@code Bearer} authorization header.
     */
    @Override
    @SuppressWarnings("unchecked")
    public Mono<SubscriptionsPage> listSubscriptions(String accessToken, String pageToken) {
        // Build the subscriptions URI with pagination, then fetch and map the response page.
        return web.get().uri(b -> buildSubscriptionsUri(pageToken))
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .onStatus(HttpStatusCode::isError, r -> Mono.error(
                        ApiException.badGateway("google subscriptions list failed")))
                .bodyToMono(Map.class)
                .map(this::toSubscriptionsPage);
    }

    /**
     * Build the YouTube subscriptions list URI, appending the pagination token when present.
     * The URI is pre-built (no UriBuilder template variables) so build(true) is used to
     * preserve any already-encoded characters.
     */
    private static URI buildSubscriptionsUri(String pageToken) {
        var ub = URI.create(SUBSCRIPTIONS_URI);
        var builder = UriComponentsBuilder.fromUri(ub)
                .queryParam("part", "snippet")
                .queryParam("mine", "true")
                .queryParam("maxResults", "50");
        if (pageToken != null && !pageToken.isBlank()) {
            builder.queryParam("pageToken", pageToken);
        }
        return builder.build(true).toUri();
    }

    @Override
    public Mono<Void> revoke(String token) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        return web.post().uri(REVOKE_URI)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                // Best-effort: swallow a non-2xx (the token may already be invalid) so a
                // disconnect always proceeds to soft-revoke the row.
                .onStatus(HttpStatusCode::isError, r -> Mono.empty())
                .bodyToMono(Void.class);
    }

    // ── response mapping ───────────────────────────────────────────────────

    private TokenResponse toTokenResponse(Map<?, ?> m) {
        // KNOWN GAP: googleSub/googleEmail are always null here — this response never
        // decodes the id_token or calls the userinfo endpoint, and nothing else in this
        // service does either, so every persisted tube_google_link row currently gets
        // google_email=null/google_sub=null. FakeGoogleApiClient (test double) DOES
        // populate both, which is why GoogleConnectControllerTest's $.googleEmail
        // assertion passes even though production traffic never sets it. Flagged as a
        // functional gap (not fixed here — implementing id_token/userinfo decoding is
        // new business logic, out of scope for a quality-only pass).
        return new TokenResponse(
                str(m, "refresh_token"),
                str(m, "access_token"),
                null,                       // google_sub — see gap note above
                null,                       // google_email — see gap note above
                str(m, "scope"));
    }

    @SuppressWarnings("unchecked")
    private SubscriptionsPage toSubscriptionsPage(Map<?, ?> body) {
        List<Subscription> out = new ArrayList<>();
        Object items = body.get("items");
        if (items instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> itemMap)) continue;
                Object snippetObj = itemMap.get("snippet");
                if (!(snippetObj instanceof Map<?, ?> snippet)) continue;
                String channelId = null;
                Object resourceId = snippet.get("resourceId");
                if (resourceId instanceof Map<?, ?> rid) {
                    channelId = str(rid, "channelId");
                }
                String title = str(snippet, "title");
                String thumb = null;
                Object thumbs = snippet.get("thumbnails");
                if (thumbs instanceof Map<?, ?> tm) {
                    Object def = tm.get("default");
                    if (def instanceof Map<?, ?> dm) thumb = str(dm, "url");
                }
                if (channelId != null && !channelId.isBlank()) {
                    out.add(new Subscription(channelId, title, thumb));
                }
            }
        }
        return new SubscriptionsPage(out, str(body, "nextPageToken"));
    }

    private static String str(Map<?, ?> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v == null ? null : v.toString();
    }
}
