package systems.snapdragon.tubebff.google;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The OAuth {@code state} CSRF token + principal binder. Proves:
 * <ul>
 *   <li>a freshly-signed state VERIFIES against the same subject+domain;</li>
 *   <li>a TAMPERED state (flipped payload/signature) is REJECTED;</li>
 *   <li>an EXPIRED state is REJECTED;</li>
 *   <li>a CROSS-PRINCIPAL replay (state minted for A/X verified against B or Y) is
 *       REJECTED — the binding can't be reused for another owner/brand.</li>
 * </ul>
 */
class GoogleConnectStateTest {

    private static GoogleConnectState state() {
        TubeGoogleProperties p = new TubeGoogleProperties();
        p.setDek(b64(seq(0, 32)));                    // satisfies cipher key (unused here)
        p.setStateHmacKey(b64(seq(40, 24)));          // 24-byte HMAC key
        return new GoogleConnectState(p);
    }

    @Test
    void validState_verifies() {
        GoogleConnectState s = state();
        String signed = s.sign("user-a", "brandx");
        assertThat(s.verify(signed, "user-a", "brandx")).isTrue();
    }

    @Test
    void tamperedPayload_rejected() {
        GoogleConnectState s = state();
        String signed = s.sign("user-a", "brandx");
        // Flip a character in the payload segment (before the '.').
        int dot = signed.indexOf('.');
        char[] chars = signed.toCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        assertThat(tampered.indexOf('.')).isEqualTo(dot);  // structure intact, content changed
        assertThat(s.verify(tampered, "user-a", "brandx")).isFalse();
    }

    @Test
    void tamperedSignature_rejected() {
        GoogleConnectState s = state();
        String signed = s.sign("user-a", "brandx");
        // Truncate the signature segment.
        String badSig = signed.substring(0, signed.length() - 2);
        assertThat(s.verify(badSig, "user-a", "brandx")).isFalse();
    }

    @Test
    void expiredState_rejected() {
        GoogleConnectState s = state();
        String expired = s.sign("user-a", "brandx", Instant.now().minusSeconds(5));
        assertThat(s.verify(expired, "user-a", "brandx")).isFalse();
    }

    @Test
    void crossPrincipalSubject_rejected() {
        GoogleConnectState s = state();
        String signed = s.sign("user-a", "brandx");
        // A state minted for user-a cannot bind user-b.
        assertThat(s.verify(signed, "user-b", "brandx")).isFalse();
    }

    @Test
    void crossPrincipalDomain_rejected() {
        GoogleConnectState s = state();
        String signed = s.sign("user-a", "brandx");
        // A state minted for brandx cannot bind brandy (cross-brand replay).
        assertThat(s.verify(signed, "user-a", "brandy")).isFalse();
    }

    @Test
    void malformedState_rejected() {
        GoogleConnectState s = state();
        assertThat(s.verify(null, "user-a", "brandx")).isFalse();
        assertThat(s.verify("no-dot-here", "user-a", "brandx")).isFalse();
        assertThat(s.verify(".", "user-a", "brandx")).isFalse();
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
