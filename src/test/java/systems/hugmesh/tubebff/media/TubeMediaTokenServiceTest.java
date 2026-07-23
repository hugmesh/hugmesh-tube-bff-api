package systems.hugmesh.tubebff.media;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TubeMediaTokenService} — no Spring context needed, the
 * service is a plain bean that takes a base64-encoded key via constructor.
 *
 * <ul>
 *   <li>Startup: missing/blank key throws {@link IllegalStateException} (fail-closed).</li>
 *   <li>sign: produces a query string with the expected four parameters.</li>
 *   <li>verify: valid token → true; expired → false; tampered sig → false;
 *       wrong subject → false; wrong domain → false; malformed base64 → false.</li>
 * </ul>
 */
class TubeMediaTokenServiceTest {

    /** A 32-byte test key, base64-encoded. */
    private static final String TEST_KEY =
            Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes());

    private TubeMediaTokenService service() {
        return new TubeMediaTokenService(TEST_KEY);
    }

    // ── startup fail-closed ───────────────────────────────────────────────────

    @Test
    void constructor_throwsWhenKeyBlank() {
        assertThatThrownBy(() -> new TubeMediaTokenService(""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("TUBE_MEDIA_KEY");
    }

    @Test
    void constructor_throwsWhenKeyNull() {
        assertThatThrownBy(() -> new TubeMediaTokenService(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("TUBE_MEDIA_KEY");
    }

    // ── sign ─────────────────────────────────────────────────────────────────

    @Test
    void sign_producesQueryStringWithAllFourParams() {
        String qs = service().sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        assertThat(qs).contains("sig=");
        assertThat(qs).contains("exp=");
        assertThat(qs).contains("sub=alice");
        assertThat(qs).contains("domain=acme");
    }

    @Test
    void sign_expIsInTheFuture() {
        long before = System.currentTimeMillis();
        String qs = service().sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        long after = System.currentTimeMillis();

        long exp = extractExp(qs);
        assertThat(exp).isGreaterThan(before);
        // Should be ~5 min from now
        assertThat(exp).isBetween(before + TubeMediaTokenService.TTL_MILLIS - 1000,
                after + TubeMediaTokenService.TTL_MILLIS + 1000);
    }

    // ── verify — happy path ──────────────────────────────────────────────────

    @Test
    void verify_validToken_returnsTrue() {
        TubeMediaTokenService svc = service();
        String qs = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");

        String sig = extractParam(qs, "sig");
        long exp   = extractExp(qs);

        assertThat(svc.verify("alice", "acme", "/acme/alice/videos/vid.mp4", sig, exp)).isTrue();
    }

    // ── verify — rejection cases ─────────────────────────────────────────────

    @Test
    void verify_expiredToken_returnsFalse() {
        TubeMediaTokenService svc = service();
        // Build a token whose exp is already in the past.
        long pastExp = System.currentTimeMillis() - 1_000L;
        // Generate a valid HMAC for the past exp so we isolate the expiry check.
        String qs = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        String sig = extractParam(qs, "sig");

        assertThat(svc.verify("alice", "acme", "/acme/alice/videos/vid.mp4", sig, pastExp)).isFalse();
    }

    @Test
    void verify_tamperedSig_returnsFalse() {
        TubeMediaTokenService svc = service();
        String qs  = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        long exp   = extractExp(qs);

        assertThat(svc.verify("alice", "acme", "/acme/alice/videos/vid.mp4",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", exp)).isFalse();
    }

    @Test
    void verify_wrongSubject_returnsFalse() {
        TubeMediaTokenService svc = service();
        String qs  = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        String sig = extractParam(qs, "sig");
        long exp   = extractExp(qs);

        // eve tries to use alice's token
        assertThat(svc.verify("eve", "acme", "/acme/alice/videos/vid.mp4", sig, exp)).isFalse();
    }

    @Test
    void verify_wrongDomain_returnsFalse() {
        TubeMediaTokenService svc = service();
        String qs  = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        String sig = extractParam(qs, "sig");
        long exp   = extractExp(qs);

        assertThat(svc.verify("alice", "other-brand", "/acme/alice/videos/vid.mp4", sig, exp)).isFalse();
    }

    @Test
    void verify_malformedBase64Sig_returnsFalse() {
        TubeMediaTokenService svc = service();
        String qs  = svc.sign("alice", "acme", "/acme/alice/videos/vid.mp4");
        long exp   = extractExp(qs);

        assertThat(svc.verify("alice", "acme", "/acme/alice/videos/vid.mp4", "!!!not-base64!!!", exp)).isFalse();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static long extractExp(String qs) {
        return Long.parseLong(extractParam(qs, "exp"));
    }

    /** Extract the raw (URL-decoded) value of a query parameter from a query string. */
    private static String extractParam(String qs, String name) {
        for (String kv : qs.split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).equals(name)) {
                return java.net.URLDecoder.decode(kv.substring(eq + 1),
                        java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("param '" + name + "' not found in: " + qs);
    }
}
