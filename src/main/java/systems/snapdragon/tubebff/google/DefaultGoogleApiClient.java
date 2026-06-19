package systems.snapdragon.tubebff.google;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Production {@link GoogleApiClient} over a reactive {@link WebClient}. Talks to:
 * <ul>
 *   <li>{@code https://oauth2.googleapis.com/token} — the authorization-code exchange +
 *       the refresh-token grant;</li>
 *   <li>{@code https://www.googleapis.com/youtube/v3/subscriptions?mine=true} — the
 *       subscribed-channels listing;</li>
 *   <li>{@code https://oauth2.googleapis.com/revoke} — token revocation (disconnect).</li>
 * </ul>
 *
 * <p>The dedicated Google OAuth Web client id/secret + redirect URI come from
 * {@link TubeGoogleProperties} (ESO {@code secret/<brand>/tube-google}). A non-2xx from
 * the token endpoint (e.g. an {@code invalid_grant} when the refresh token was revoked)
 * surfaces as an error Mono so {@code SubscriptionsSyncService} can mark
 * {@code reauth_required} and stop.
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
                .onStatus(s -> s.isError(), r -> Mono.error(
                        ApiException.badGateway("google token exchange failed")))
                .bodyToMono(Map.class)
                .map(this::toTokenResponse);
    }

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
                .onStatus(s -> s.isError(), r -> Mono.error(
                        ApiException.badGateway("google refresh failed")))
                .bodyToMono(Map.class)
                .map(m -> str(m, "access_token"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public Mono<SubscriptionsPage> listSubscriptions(String accessToken, String pageToken) {
        return web.get().uri(b -> {
                    var ub = java.net.URI.create(SUBSCRIPTIONS_URI);
                    var builder = org.springframework.web.util.UriComponentsBuilder.fromUri(ub)
                            .queryParam("part", "snippet")
                            .queryParam("mine", "true")
                            .queryParam("maxResults", "50");
                    if (pageToken != null && !pageToken.isBlank()) {
                        builder.queryParam("pageToken", pageToken);
                    }
                    return builder.build(true).toUri();
                })
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .onStatus(s -> s.isError(), r -> Mono.error(
                        ApiException.badGateway("google subscriptions list failed")))
                .bodyToMono(Map.class)
                .map(this::toSubscriptionsPage);
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
                .onStatus(s -> s.isError(), r -> Mono.empty())
                .bodyToMono(Void.class);
    }

    // ── response mapping ───────────────────────────────────────────────────

    private TokenResponse toTokenResponse(Map<?, ?> m) {
        return new TokenResponse(
                str(m, "refresh_token"),
                str(m, "access_token"),
                null,                       // google_sub/email come from the id_token/userinfo
                null,                       // (not decoded here — display-only, populated later)
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
