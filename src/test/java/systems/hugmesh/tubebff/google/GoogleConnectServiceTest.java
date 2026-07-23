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
 * {@link GoogleConnectService} over the REAL link repo + real cipher/state + a fake
 * {@link GoogleApiClient}. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL — happy path</b>: a state-verified callback exchanges the
 *       code, stores the refresh token as CIPHERTEXT (never plaintext), and stamps the
 *       owner + brand from the JWT.</li>
 *   <li><b>DENY</b>: a BAD/tampered state is rejected BEFORE any code exchange (the fake
 *       records zero exchange calls).</li>
 *   <li><b>CROSS-USER / domain isolation</b>: the stored link is keyed on the connecting
 *       principal's (subject, brand); a different brand can't see it.</li>
 *   <li><b>disconnect</b>: best-effort revoke at Google + soft-revoke the row.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({PostgresSliceTestConfig.class, TubeGoogleLinkRepository.class})
@ActiveProfiles("test")
class GoogleConnectServiceTest extends PostgresTestSupport {

    @Autowired TubeGoogleLinkRepository links;

    private FakeGoogleApiClient google;
    private TokenCipher cipher;
    private GoogleConnectState state;
    private GoogleConnectService service;

    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final String ISS_X = "https://id.brandx.example";
    private static final String ISS_Y = "https://id.brandy.example";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private String user(String tag) { return "conn-" + tag + "-" + SEQ.incrementAndGet(); }

    @BeforeEach
    void setUp() {
        TubeGoogleProperties props = props();
        google = new FakeGoogleApiClient();
        cipher = new TokenCipher(props);
        state = new GoogleConnectState(props);
        PersonalOwner owner = new PersonalOwner(MULTI);
        service = new GoogleConnectService(google, cipher, state, links, props, owner);
    }

    @Nested
    class HappyPath {

        @Test
        void callback_storesCiphertextNotPlaintext_stampedWithOwnerAndBrand() {
            String u = user("ok");
            Authentication auth = principal(ISS_X, u, "tube");
            String validState = state.sign(u, "brandx");

            TubeGoogleLink link = service.callback("auth-code-1", validState, auth).block();
            assertThat(link).isNotNull();
            assertThat(link.userSubject()).isEqualTo(u);
            assertThat(link.domain()).isEqualTo("brandx");          // from the issuer
            assertThat(google.exchangeCalls.get()).isEqualTo(1);    // the exchange fired
            // The crown jewel is stored ONLY as ciphertext — never the cleartext token.
            assertThat(link.refreshTokenCiphertext()).isNotBlank();
            assertThat(link.refreshTokenCiphertext()).isNotEqualTo("refresh-token-xyz");
            // ...and it decrypts back to the token the exchange returned.
            assertThat(cipher.decrypt(link.refreshTokenCiphertext())).isEqualTo("refresh-token-xyz");

            // The live link is resolvable for the owner in their brand.
            assertThat(links.findLive("brandx", u).block()).isNotNull();
        }

        @Test
        void callback_reConnect_supersedesPriorLiveLink() {
            String u = user("reconnect");
            Authentication auth = principal(ISS_X, u, "tube");
            service.callback("code-1", state.sign(u, "brandx"), auth).block();
            TubeGoogleLink second = service.callback("code-2", state.sign(u, "brandx"), auth).block();

            // Only one LIVE link remains (the prior was soft-revoked).
            assertThat(links.findLive("brandx", u).block().id()).isEqualTo(second.id());
        }
    }

    @Nested
    class StateRejection {

        @Test
        void callback_badState_rejected_noCodeExchange() {
            String u = user("badstate");
            Authentication auth = principal(ISS_X, u, "tube");
            // A state minted for a DIFFERENT user (cross-principal) must be rejected.
            String foreignState = state.sign("someone-else", "brandx");

            assertThatThrownBy(() -> service.callback("code", foreignState, auth).block())
                    .isInstanceOf(ApiException.class);
            assertThat(google.exchangeCalls.get()).isEqualTo(0);   // NO exchange happened
            assertThat(links.findLive("brandx", u).blockOptional()).isEmpty();
        }

        @Test
        void callback_stateFromAnotherBrand_rejected() {
            String u = user("xbrand");
            Authentication auth = principal(ISS_X, u, "tube");
            // A state signed for brandY can't bind a brandX callback.
            String yState = state.sign(u, "brandy");
            assertThatThrownBy(() -> service.callback("code", yState, auth).block())
                    .isInstanceOf(ApiException.class);
            assertThat(google.exchangeCalls.get()).isEqualTo(0);
        }
    }

    @Nested
    class Disconnect {

        @Test
        void disconnect_revokesAtGoogle_andSoftRevokesRow() {
            String u = user("disc");
            Authentication auth = principal(ISS_X, u, "tube");
            service.callback("code", state.sign(u, "brandx"), auth).block();
            assertThat(links.findLive("brandx", u).block()).isNotNull();

            service.disconnect(auth).block();
            assertThat(google.revokeCalls.get()).isEqualTo(1);        // best-effort revoke fired
            assertThat(links.findLive("brandx", u).blockOptional()).isEmpty();  // soft-revoked
        }
    }

    @Nested
    class FailClosed {

        @Test
        void authorizeUrl_unresolvedIssuer_failsClosed() {
            // An issuer the multi-brand registry doesn't know -> domain null -> 403.
            Authentication auth = principal("https://id.unknown.example", user("unk"), "tube");
            assertThatThrownBy(() -> service.authorizeUrl(auth).block())
                    .isInstanceOf(ApiException.class);
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
        p.setClientId("test-client");
        p.setClientSecret("test-secret");
        p.setRedirectUri("https://brandx.example/bff/tube/google-connect/callback");
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
