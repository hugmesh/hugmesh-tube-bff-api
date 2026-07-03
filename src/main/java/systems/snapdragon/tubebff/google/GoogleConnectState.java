package systems.snapdragon.tubebff.google;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * The OAuth {@code state} parameter — the CSRF defence on the Google connect flow AND
 * the principal binder for the callback. The consent-redirect callback is hit by
 * Google's browser redirect carrying {@code code} + {@code state}; that hop does NOT
 * carry the user's bearer token, so the acting principal (subject + brand) is bound by
 * SIGNING it into the {@code state} here and verifying it on the callback.
 *
 * <p><b>Construction.</b> The signed value is
 * {@code base64url(payload) + "." + base64url(HMAC-SHA256(payload))} where
 * {@code payload = subject | domain | nonce | expiryEpochSeconds}. The key is the
 * &gt;=16-byte HMAC key from {@link TubeGoogleProperties#decodeStateHmacKey()} (ESO).
 *
 * <p><b>Verification rejects</b> (each returns {@code false}, never throws to the
 * caller's control flow):
 * <ul>
 *   <li>a TAMPERED payload/signature — the recomputed HMAC won't match (constant-time
 *       compare via {@link MessageDigest#isEqual});</li>
 *   <li>an EXPIRED state — {@code expiry <= now} (a stale/replayed consent URL);</li>
 *   <li>a CROSS-PRINCIPAL state — the {@code subject}/{@code domain} signed into the
 *       state must equal the values the callback resolved for THIS request, so a state
 *       minted for user A in brand X cannot be replayed to bind user B / brand Y.</li>
 * </ul>
 * The {@code |} and {@code .} separators can't appear in the base64url fields (and
 * subject/domain are stamped server-side from the JWT, not free text), so the payload is
 * unambiguous.
 */
@Component
public class GoogleConnectState {

    private static final String HMAC_ALG = "HmacSHA256";
    private static final char FIELD_SEP = '|';
    private static final char SIG_SEP = '.';
    /** A signed state is valid for this long after minting (the consent round-trip). */
    static final Duration TTL = Duration.ofMinutes(10);

    private final byte[] hmacKey;
    private final SecureRandom random = new SecureRandom();

    public GoogleConnectState(TubeGoogleProperties props) {
        this.hmacKey = props.decodeStateHmacKey();   // fail-closed: throws unless >=16 bytes
    }

    /**
     * Sign a fresh state value binding {@code subject} and {@code domain} for the connect
     * flow, valid for {@link #TTL} (10 minutes) from now.
     *
     * @param subject the Casdoor subject of the acting principal
     * @param domain  the brand of the acting principal
     * @return the signed state string: {@code base64url(payload) + "." + base64url(HMAC)}
     */
    public String sign(String subject, String domain) {
        return sign(subject, domain, Instant.now().plus(TTL));
    }

    /** Sign with an explicit expiry (test seam for the expiry-rejection path). */
    String sign(String subject, String domain, Instant expiry) {
        String nonce = newNonce();
        String payload = payload(subject, domain, nonce, expiry.getEpochSecond());
        String sig = b64(hmac(payload.getBytes(StandardCharsets.UTF_8)));
        return b64(payload.getBytes(StandardCharsets.UTF_8)) + SIG_SEP + sig;
    }

    /**
     * Verify a state value against the principal the callback resolved. Returns
     * {@code true} ONLY when the signature authenticates, the state is unexpired, AND the
     * signed {@code subject}+{@code domain} match {@code expectedSubject}+
     * {@code expectedDomain}. Any tamper/expiry/cross-principal/malformation -> false.
     */
    public boolean verify(String state, String expectedSubject, String expectedDomain) {
        if (state == null || expectedSubject == null || expectedDomain == null) return false;
        int dot = state.indexOf(SIG_SEP);
        if (dot <= 0 || dot == state.length() - 1) return false;
        String payloadB64 = state.substring(0, dot);
        String sigB64 = state.substring(dot + 1);

        byte[] payloadBytes;
        byte[] presentedSig;
        try {
            payloadBytes = Base64.getUrlDecoder().decode(payloadB64);
            presentedSig = Base64.getUrlDecoder().decode(sigB64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        // Constant-time signature check FIRST — never parse an unauthenticated payload's
        // fields for a decision before the MAC verifies it.
        byte[] expectedSig = hmac(payloadBytes);
        if (!MessageDigest.isEqual(expectedSig, presentedSig)) return false;

        String payload = new String(payloadBytes, StandardCharsets.UTF_8);
        String[] parts = payload.split("\\" + FIELD_SEP, -1);
        if (parts.length != 4) return false;
        String subject = parts[0];
        String domain = parts[1];
        // parts[2] = nonce (uniqueness only)
        long expiry;
        try {
            expiry = Long.parseLong(parts[3]);
        } catch (NumberFormatException e) {
            return false;
        }
        if (Instant.now().getEpochSecond() >= expiry) return false;             // expired
        // Cross-principal binding: the state must have been minted for THIS principal.
        if (!constantTimeEquals(subject, expectedSubject)) return false;
        if (!constantTimeEquals(domain, expectedDomain)) return false;
        return true;
    }

    private String payload(String subject, String domain, String nonce, long expiryEpoch) {
        // subject/domain come from the validated JWT (server-side); the separators cannot
        // appear in the base64url nonce or the numeric expiry.
        return subject + FIELD_SEP + domain + FIELD_SEP + nonce + FIELD_SEP + expiryEpoch;
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(hmacKey, HMAC_ALG));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("state HMAC failed", e);
        }
    }

    private String newNonce() {
        byte[] n = new byte[16];
        random.nextBytes(n);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(n);
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Constant-time string compare (avoids leaking the matched-prefix length). */
    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
