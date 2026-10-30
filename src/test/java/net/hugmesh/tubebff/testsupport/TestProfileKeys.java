package net.hugmesh.tubebff.testsupport;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * TEST-ONLY, non-secret key fixtures for the full-context ({@code @SpringBootTest}) tests.
 *
 * <p>{@code TokenCipher} / {@code GoogleConnectState} and {@code TubeMediaTokenService} all
 * FAIL CLOSED at construction on a missing or short key, so the context-load and
 * OpenAPI-dump tests need SOME well-formed value present. Production never sees these:
 * deployed brands get {@code tube.google.*} and {@code TUBE_MEDIA_KEY} from ESO/Vault.
 *
 * <p><b>Why they are built here and not written in {@code application-test.yml}:</b> that
 * file lives under {@code src/main/resources}, so it ships inside the deployable jar, and a
 * base64 literal next to a {@code key:} name is exactly what secret scanners flag. The
 * values are assembled at runtime from deterministic, obviously-fake byte runs instead, so
 * no key-shaped literal exists in the source tree and nothing key-like ships in the jar.
 *
 * <ul>
 *   <li>DEK = 32 bytes {@code 0x00..0x1f} (AES-256, must decode to exactly 32 bytes).</li>
 *   <li>Google-connect state HMAC key = 24 bytes {@code 0x20..0x37} (must be &gt;= 16).</li>
 *   <li>Media URL-signing key = the 32 ASCII digits {@code 0123456789} repeated and cut
 *       to 32 — the same fixture {@code TubeMediaTokenServiceTest} signs with.</li>
 * </ul>
 */
public final class TestProfileKeys {

    private TestProfileKeys() {
    }

    /** base64 of the 32 bytes {@code 0x00..0x1f}. */
    public static String dek() {
        return base64(byteRun(0x00, 32));
    }

    /** base64 of the 24 bytes {@code 0x20..0x37}. */
    public static String stateHmacKey() {
        return base64(byteRun(0x20, 24));
    }

    /** base64 of 32 ASCII digits: {@code "0123456789"} repeated, first 32 characters. */
    public static String mediaKey() {
        String digits = "0123456789".repeat(4).substring(0, 32);
        return base64(digits.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Publishes every fixture key into a {@code @SpringBootTest} context. Call it from a
     * {@code @DynamicPropertySource} method on the test class.
     */
    public static void register(DynamicPropertyRegistry registry) {
        registry.add("tube.google.dek", TestProfileKeys::dek);
        registry.add("tube.google.state-hmac-key", TestProfileKeys::stateHmacKey);
        registry.add("TUBE_MEDIA_KEY", TestProfileKeys::mediaKey);
    }

    private static byte[] byteRun(int first, int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (first + i);
        }
        return out;
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
