package net.hugmesh.tubebff.google;

import reactor.core.publisher.Mono;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A scriptable in-memory {@link GoogleApiClient} for the service/sync tests — no network,
 * no real creds. Records call counts so a test can assert the code-exchange did NOT fire
 * (e.g. on a bad state), and lets a test force the refresh to FAIL (the reauth_required
 * path). Subscription pages are enqueued and returned in order.
 */
class FakeGoogleApiClient implements GoogleApiClient {

    final AtomicInteger exchangeCalls = new AtomicInteger();
    final AtomicInteger refreshCalls = new AtomicInteger();
    final AtomicInteger revokeCalls = new AtomicInteger();
    final AtomicInteger listCalls = new AtomicInteger();

    /** When set, refreshAccessToken errors (simulating a revoked/expired refresh token). */
    boolean failRefresh = false;
    /** The refresh token the exchange returns (null simulates "no refresh token"). */
    String exchangeRefreshToken = "refresh-token-xyz";
    String exchangeGoogleSub = "g-sub-1";
    String exchangeGoogleEmail = "user@example.com";

    private final Deque<SubscriptionsPage> pages = new ArrayDeque<>();

    void enqueuePage(SubscriptionsPage page) {
        pages.add(page);
    }

    @Override
    public Mono<TokenResponse> exchangeCode(String code) {
        exchangeCalls.incrementAndGet();
        return Mono.just(new TokenResponse(exchangeRefreshToken, "access-1",
                exchangeGoogleSub, exchangeGoogleEmail,
                "https://www.googleapis.com/auth/youtube.readonly"));
    }

    @Override
    public Mono<String> refreshAccessToken(String refreshToken) {
        refreshCalls.incrementAndGet();
        if (failRefresh) {
            return Mono.error(new RuntimeException("invalid_grant"));
        }
        return Mono.just("access-token-fresh");
    }

    @Override
    public Mono<SubscriptionsPage> listSubscriptions(String accessToken, String pageToken) {
        listCalls.incrementAndGet();
        SubscriptionsPage page = pages.poll();
        return Mono.just(page != null ? page : new SubscriptionsPage(List.of(), null));
    }

    @Override
    public Mono<Void> revoke(String token) {
        revokeCalls.incrementAndGet();
        return Mono.empty();
    }
}
