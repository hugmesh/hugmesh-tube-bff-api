package systems.snapdragon.tubebff.google;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AES-256-GCM at-rest cipher for the crown-jewel refresh token. Proves:
 * <ul>
 *   <li>round-trip (encrypt then decrypt == plaintext);</li>
 *   <li>the stored ciphertext is NOT the plaintext (and differs per encrypt — fresh IV);</li>
 *   <li>FAIL-CLOSED on a wrong DEK (tag mismatch), a tampered blob, and a missing/short
 *       DEK (construction rejects).</li>
 * </ul>
 */
class TokenCipherTest {

    private static final String DEK_A = b64(bytesSeq(0, 32));      // 32 bytes -> AES-256
    private static final String DEK_B = b64(bytesSeq(100, 32));    // a DIFFERENT 32-byte key
    private static final String STATE_KEY = b64(bytesSeq(0, 24));  // satisfies state key (unused here)

    private static TokenCipher cipher(String dek) {
        TubeGoogleProperties p = new TubeGoogleProperties();
        p.setDek(dek);
        p.setStateHmacKey(STATE_KEY);
        return new TokenCipher(p);
    }

    @Test
    void roundTrip_decryptsBackToPlaintext() {
        TokenCipher c = cipher(DEK_A);
        String token = "1//0gRefreshTokenCrownJewel-abc123";
        String blob = c.encrypt(token);
        assertThat(c.decrypt(blob)).isEqualTo(token);
    }

    @Test
    void ciphertext_isNotPlaintext_andDiffersPerEncrypt() {
        TokenCipher c = cipher(DEK_A);
        String token = "refresh-secret";
        String blob1 = c.encrypt(token);
        String blob2 = c.encrypt(token);
        // Stored value is not the cleartext...
        assertThat(blob1).doesNotContain(token);
        assertThat(Base64.getDecoder().decode(blob1)).isNotEqualTo(token.getBytes());
        // ...and a fresh random IV makes two encrypts of the same token differ.
        assertThat(blob1).isNotEqualTo(blob2);
        // ...yet both decrypt back to the same plaintext.
        assertThat(c.decrypt(blob1)).isEqualTo(token);
        assertThat(c.decrypt(blob2)).isEqualTo(token);
    }

    @Test
    void wrongDek_failsClosed_neverReturnsPlaintext() {
        String blob = cipher(DEK_A).encrypt("secret");
        assertThatThrownBy(() -> cipher(DEK_B).decrypt(blob))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void tamperedCiphertext_failsClosed() {
        TokenCipher c = cipher(DEK_A);
        String blob = c.encrypt("secret");
        byte[] raw = Base64.getDecoder().decode(blob);
        raw[raw.length - 1] ^= 0x01;                 // flip a tag bit
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThatThrownBy(() -> c.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void missingDek_failsClosedAtConstruction() {
        TubeGoogleProperties p = new TubeGoogleProperties();
        p.setStateHmacKey(STATE_KEY);
        // dek null/blank
        assertThatThrownBy(() -> new TokenCipher(p)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void shortDek_failsClosedAtConstruction() {
        TubeGoogleProperties p = new TubeGoogleProperties();
        p.setDek(b64(bytesSeq(0, 16)));               // 16 bytes -> NOT AES-256
        p.setStateHmacKey(STATE_KEY);
        assertThatThrownBy(() -> new TokenCipher(p)).isInstanceOf(IllegalStateException.class);
    }

    private static byte[] bytesSeq(int start, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (start + i);
        return b;
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
