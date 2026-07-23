package systems.hugmesh.tubebff.google;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import systems.hugmesh.commons.security.DomainRegistry;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.tubebff.support.PostgresSliceTestConfig;
import systems.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link SubscriptionsSyncService} over the REAL link + subscription repos + a fake
 * {@link GoogleApiClient}. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL — sync</b>: pages subscriptions.list and UPSERTs each channel;
 *       walks {@code nextPageToken} across pages.</li>
 *   <li><b>IDEMPOTENT UPSERT</b>: a re-sync of the same channels does NOT duplicate rows —
 *       the (domain,user,channel) row updates in place.</li>
 *   <li><b>reauth_required + STOP</b>: when the refresh FAILS, the link is flagged
 *       reauth_required and the sync errors WITHOUT looping / listing; a subsequent sync of
 *       a flagged link is refused up front (no second refresh attempt).</li>
 *   <li><b>DENY</b>: a sync with no live link is a 409.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({PostgresSliceTestConfig.class, TubeGoogleLinkRepository.class, TubeSubscriptionRepository.class})
@ActiveProfiles("test")
class SubscriptionsSyncServiceTest extends PostgresTestSupport {

    @Autowired TubeGoogleLinkRepository links;
    @Autowired TubeSubscriptionRepository subs;

    private FakeGoogleApiClient google;
    private TokenCipher cipher;
    private SubscriptionsSyncService service;

    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final String ISS_X = "https://id.brandx.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "sync-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        TubeGoogleProperties props = props();
        google = new FakeGoogleApiClient();
        cipher = new TokenCipher(props);
        PersonalOwner owner = new PersonalOwner(MULTI);
        service = new SubscriptionsSyncService(google, cipher, links, subs, owner);
    }

    /** Seed a live Google link for the owner with a real ciphertext refresh token. */
    private void seedLink(String domain, String subject) {
        links.insert(domain, subject, "g-sub", "u@example.com",
                cipher.encrypt("refresh-token-xyz"), "v1",
                "https://www.googleapis.com/auth/youtube.readonly").block();
    }

    @Nested
    class Sync {

        @Test
        void sync_upsertsChannelsAcrossPages() {
            String u = user("pages");
            seedLink("brandx", u);
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("chan-1", "Channel One", "t1"),
                    new GoogleApiClient.Subscription("chan-2", "Channel Two", "t2")), "page-2"));
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("chan-3", "Channel Three", "t3")), null));

            Integer count = service.sync(principal(ISS_X, u, "tube")).block();
            assertThat(count).isEqualTo(3);
            assertThat(google.refreshCalls.get()).isEqualTo(1);
            assertThat(google.listCalls.get()).isEqualTo(2);              // followed nextPageToken

            List<TubeSubscription> stored = subs.listForOwner("brandx", u).collectList().block();
            assertThat(stored).hasSize(3);
            assertThat(stored).extracting(TubeSubscription::channelId)
                    .containsExactlyInAnyOrder("chan-1", "chan-2", "chan-3");
        }

        @Test
        void reSync_isIdempotent_noDuplicates_updatesInPlace() {
            String u = user("idem");
            seedLink("brandx", u);
            // First sync: one channel.
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("chan-x", "Old Title", "old")), null));
            service.sync(principal(ISS_X, u, "tube")).block();

            // Second sync: same channel id, new title — must UPDATE not duplicate.
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("chan-x", "New Title", "new")), null));
            service.sync(principal(ISS_X, u, "tube")).block();

            List<TubeSubscription> stored = subs.listForOwner("brandx", u).collectList().block();
            assertThat(stored).hasSize(1);                               // no duplicate row
            assertThat(stored.get(0).channelTitle()).isEqualTo("New Title");  // updated in place
        }
    }

    @Nested
    class ReauthRequired {

        @Test
        void refreshFailure_marksReauthRequired_andStops() {
            String u = user("reauth");
            seedLink("brandx", u);
            google.failRefresh = true;
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("never", "Never Synced", null)), null));

            assertThatThrownBy(() -> service.sync(principal(ISS_X, u, "tube")).block())
                    .isInstanceOf(ApiException.class);

            // The refresh was attempted ONCE, the list was NEVER reached (no loop).
            assertThat(google.refreshCalls.get()).isEqualTo(1);
            assertThat(google.listCalls.get()).isEqualTo(0);
            // The link is flagged so the UI prompts a re-connect.
            assertThat(links.findLive("brandx", u).block().reauthRequired()).isTrue();
            // ...and nothing was synced.
            assertThat(subs.listForOwner("brandx", u).collectList().block()).isEmpty();
        }

        @Test
        void alreadyFlaggedLink_refusedUpFront_noSecondRefresh() {
            String u = user("flagged");
            seedLink("brandx", u);
            google.failRefresh = true;
            assertThatThrownBy(() -> service.sync(principal(ISS_X, u, "tube")).block())
                    .isInstanceOf(ApiException.class);
            int refreshesAfterFirst = google.refreshCalls.get();

            // A second sync of the now-flagged link must NOT attempt another refresh.
            assertThatThrownBy(() -> service.sync(principal(ISS_X, u, "tube")).block())
                    .isInstanceOf(ApiException.class);
            assertThat(google.refreshCalls.get()).isEqualTo(refreshesAfterFirst);
        }
    }

    @Nested
    class Deny {

        @Test
        void sync_withNoLiveLink_is409() {
            String u = user("nolink");
            assertThatThrownBy(() -> service.sync(principal(ISS_X, u, "tube")).block())
                    .isInstanceOf(ApiException.class)
                    .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(409));
        }

        @Test
        void list_isOwnerScoped_doesNotSeeAnotherBrand() {
            String u = user("scope");
            seedLink("brandx", u);
            google.enqueuePage(new GoogleApiClient.SubscriptionsPage(List.of(
                    new GoogleApiClient.Subscription("c", "C", null)), null));
            service.sync(principal(ISS_X, u, "tube")).block();

            // Same subject in brandY has no subscriptions of its own.
            assertThat(subs.listForOwner("brandy", u).collectList().block()).isEmpty();
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────
    private static Authentication principal(String issuer, String subject, String... roles) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).claim("iss", issuer).issuer(issuer)
                .claim("roles", List.of(roles)).build();
        List<GrantedAuthority> auths = Stream.concat(
                Stream.of(new SimpleGrantedAuthority("ROLE_USER")),
                Stream.of(roles).map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase())))
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(jwt, "n/a", auths);
    }

    private static TubeGoogleProperties props() {
        TubeGoogleProperties p = new TubeGoogleProperties();
        p.setDek(b64(seq(0, 32)));
        p.setStateHmacKey(b64(seq(64, 24)));
        return p;
    }

    private static byte[] seq(int start, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (start + i);
        return b;
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
