package systems.hugmesh.tubebff.google;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Pages a connected user's YouTube {@code subscriptions.list?mine=true} and idempotently
 * UPSERTs each channel into {@code tube_subscription}.
 *
 * <p>Flow: resolve the owner (fail-closed, single-domain) → load their LIVE Google link →
 * decrypt the refresh token in memory → mint a fresh access token → page subscriptions
 * (following {@code nextPageToken}) → UPSERT each channel → return the live subscription
 * list.
 *
 * <p><b>reauth_required STOP (no loop).</b> If the refresh exchange FAILS (the refresh
 * token was revoked/expired at Google), the link is marked {@code reauth_required=true}
 * and the sync STOPS with a 4xx — it does NOT retry. The UI then prompts a re-connect. A
 * link already flagged {@code reauth_required} is refused up front for the same reason.
 */
@Service
public class SubscriptionsSyncService {

    private static final Logger log = LoggerFactory.getLogger(SubscriptionsSyncService.class);

    /** A hard cap on pages walked per sync (defence against a pathological pagination
     *  loop). 50 items/page * 100 pages = 5000 channels — well beyond any real account. */
    private static final int MAX_PAGES = 100;

    private final GoogleApiClient google;
    private final TokenCipher cipher;
    private final TubeGoogleLinkRepository links;
    private final TubeSubscriptionRepository subs;
    private final PersonalOwner owner;

    public SubscriptionsSyncService(GoogleApiClient google, TokenCipher cipher,
                                    TubeGoogleLinkRepository links, TubeSubscriptionRepository subs,
                                    PersonalOwner owner) {
        this.google = google;
        this.cipher = cipher;
        this.links = links;
        this.subs = subs;
        this.owner = owner;
    }

    /**
     * Return the owner's currently stored subscribed channels from the local DB — no
     * Google network call. Owner + domain scoped (single-domain, fail-closed).
     *
     * @param auth the authenticated principal
     * @return a {@code Flux} of {@link TubeSubscription} rows ordered by channel title;
     *         errors (403) when the owner cannot be resolved
     */
    public Flux<TubeSubscription> list(Authentication auth) {
        return Mono.fromCallable(() -> owner.resolve(auth))
                .flatMapMany(o -> subs.listForOwner(o.domain(), o.subject()));
    }

    /**
     * Sync the owner's YouTube subscriptions from Google and idempotently UPSERT each
     * channel into {@code tube_subscription}. Pages all pages (up to {@value #MAX_PAGES}
     * = 5000 channels). Returns the total UPSERTed count.
     *
     * <p>Errors without retry:
     * <ul>
     *   <li>409 — no live Google link (user must connect first);</li>
     *   <li>403 — the link is already flagged {@code reauth_required} (reconnect needed);</li>
     *   <li>403 — the refresh exchange failed (revoked/expired); marks {@code
     *       reauth_required} before surfacing the error.</li>
     * </ul>
     *
     * @param auth the authenticated principal
     * @return a {@code Mono} emitting the count of channels UPSERTed; errors on the
     *         conditions above or when the owner cannot be resolved
     */
    public Mono<Integer> sync(Authentication auth) {
        return Mono.fromCallable(() -> owner.resolve(auth))
                .flatMap(o -> links.findLive(o.domain(), o.subject())
                        .switchIfEmpty(Mono.error(ApiException.conflict(
                                "no Google connection; connect first")))
                        .flatMap(link -> syncLink(o, link)));
    }

    private Mono<Integer> syncLink(PersonalOwner.Owner o, TubeGoogleLink link) {
        if (link.reauthRequired()) {
            // Already flagged — don't burn a refresh attempt; prompt a re-connect.
            return Mono.error(ApiException.forbidden(
                    "Google connection needs re-authentication; reconnect first"));
        }
        // fromCallable surfaces any RuntimeException from cipher.decrypt as an onError
        // signal; onErrorResume marks the link as needing re-authentication and propagates
        // a 403 — an undecryptable blob can never be refreshed.
        return Mono.fromCallable(() -> cipher.decrypt(link.refreshTokenCiphertext()))
                .onErrorResume(RuntimeException.class, e ->
                        links.markReauthRequired(o.domain(), o.subject())
                                .then(Mono.error(ApiException.forbidden(
                                        "stored Google token is unreadable; reconnect required"))))
                .flatMap(refresh -> google.refreshAccessToken(refresh)
                        // Refresh FAILED (revoked/expired): mark reauth_required + STOP (no retry).
                        .onErrorResume(e -> links.markReauthRequired(o.domain(), o.subject())
                                .then(Mono.error(ApiException.forbidden(
                                        "Google refresh failed; re-authentication required"))))
                        .flatMap(accessToken -> pageAndUpsert(o, accessToken)));
    }

    /** Walk all subscription pages (bounded) and UPSERT each channel; return the count. */
    private Mono<Integer> pageAndUpsert(PersonalOwner.Owner o, String accessToken) {
        AtomicInteger count = new AtomicInteger();
        return walk(o, accessToken, null, 0, count)
                .thenReturn(count)
                .map(AtomicInteger::get)
                .doOnNext(n -> log.info("[tube-google] synced {} subscriptions for {} in {}",
                        n, o.subject(), o.domain()));
    }

    private Mono<Void> walk(PersonalOwner.Owner o, String accessToken, String pageToken,
                            int pageNo, AtomicInteger count) {
        if (pageNo >= MAX_PAGES) {
            return Mono.empty();   // bounded — stop following pages
        }
        return google.listSubscriptions(accessToken, pageToken)
                .flatMap(page -> Flux.fromIterable(page.items())
                        .concatMap(item -> subs.upsert(o.domain(), o.subject(), item.channelId(),
                                        item.channelTitle(), item.thumbnailUrl())
                                .doOnNext(n -> count.incrementAndGet()))
                        .then(Mono.defer(() -> {
                            String next = page.nextPageToken();
                            return (next == null || next.isBlank())
                                    ? Mono.empty()
                                    : walk(o, accessToken, next, pageNo + 1, count);
                        })));
    }
}
