package systems.snapdragon.tubebff.media;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Signs and verifies short-TTL media access tokens for the tube content PVC.
 *
 * <p><b>Token shape.</b> The signed query string appended to a tube-media Nginx URL:
 * <pre>
 *   sig=&lt;base64url&gt;&amp;exp=&lt;epoch-millis&gt;&amp;sub=&lt;owner-subject&gt;&amp;domain=&lt;domain&gt;
 * </pre>
 *
 * <p><b>HMAC input.</b> {@code "${sub}|${domain}|${path}|${exp}"} (UTF-8 bytes)
 * over the canonical four-field string — binding the token to one user, one brand,
 * one path segment AND one expiry epoch so neither cross-user reuse nor expiry
 * extension is possible without a new HMAC.
 *
 * <p><b>Key.</b> 32-byte key from the ESO-supplied k8s secret via env var
 * {@code TUBE_MEDIA_KEY} (base64-encoded). The service FAILS CLOSED at startup
 * ({@link IllegalStateException}) when the key is absent or blank — a missing key
 * is a misconfiguration, not a degraded mode.
 *
 * <p><b>TTL.</b> 5 minutes (300 s). The nginx sidecar enforces the expiry at serve time
 * (via Lua / auth_request pointing at {@code /bff/tube/media/verify}); this service
 * provides both the sign and verify sides.
 *
 * <p><b>Constant-time verify.</b> {@link MessageDigest#isEqual} is used for the HMAC
 * comparison so timing cannot leak the expected MAC byte-by-byte.
 */
@Service
public final class TubeMediaTokenService {

    /** 5-minute short TTL in milliseconds. */
    static final long TTL_MILLIS = 300_000L;

    private static final String HMAC_ALG = "HmacSHA256";

    private final byte[] keyBytes;

    /**
     * Construct the service and decode the HMAC key.
     *
     * @param rawKey the base64-encoded 32-byte key from {@code TUBE_MEDIA_KEY}; must
     *               not be blank — fail-closed at startup if absent or empty.
     */
    public TubeMediaTokenService(
            @Value("${TUBE_MEDIA_KEY:}") String rawKey) {
        if (rawKey == null || rawKey.isBlank()) {
            throw new IllegalStateException(
                    "TUBE_MEDIA_KEY is not set — tube media URL signing cannot function "
                    + "(ESO secret must be present before the pod starts)");
        }
        this.keyBytes = Base64.getDecoder().decode(rawKey.trim());
    }

    /**
     * Sign a media access token for the given principal + path.
     *
     * @param ownerSubject the Casdoor subject of the user who owns the content
     * @param domain       the brand/domain this token is scoped to
     * @param path         the content path (e.g. {@code /acme/alice/videos/vid.mp4})
     * @return the signed query string {@code sig=...&exp=...&sub=...&domain=...}
     *         ready to append to a tube-media Nginx URL
     */
    public String sign(String ownerSubject, String domain, String path) {
        long exp = System.currentTimeMillis() + TTL_MILLIS;
        byte[] mac = hmac(ownerSubject, domain, path, exp);
        String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(mac);
        return "sig=" + urlEncode(sig)
                + "&exp=" + exp
                + "&sub=" + urlEncode(ownerSubject)
                + "&domain=" + urlEncode(domain);
    }

    /**
     * Verify a media token: constant-time HMAC comparison AND expiry check.
     *
     * @param ownerSubject the subject claim from the requesting JWT
     * @param domain       the domain claim from the requesting JWT
     * @param path         the content path being requested
     * @param sig          the {@code sig} query parameter value (base64url)
     * @param exp          the {@code exp} query parameter value (epoch millis)
     * @return {@code true} iff the HMAC is valid for the given inputs AND
     *         {@code exp > System.currentTimeMillis()} (not yet expired)
     */
    public boolean verify(String ownerSubject, String domain, String path, String sig, long exp) {
        // Expiry check first — a short-circuit that is not timing-sensitive.
        if (exp <= System.currentTimeMillis()) {
            return false;
        }
        byte[] expected = hmac(ownerSubject, domain, path, exp);
        byte[] provided;
        try {
            provided = Base64.getUrlDecoder().decode(sig);
        } catch (IllegalArgumentException e) {
            return false;   // malformed base64 — reject
        }
        // Constant-time comparison: MessageDigest.isEqual pads to the longer length
        // before comparing so a length mismatch does NOT short-circuit.
        return MessageDigest.isEqual(expected, provided);
    }

    // ── internal ──────────────────────────────────────────────────────────────

    /** Compute HMAC-SHA256 over {@code "${sub}|${domain}|${path}|${exp}"}. */
    private byte[] hmac(String sub, String domain, String path, long exp) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALG));
            String input = sub + "|" + domain + "|" + path + "|" + exp;
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 failed (JCA misconfiguration)", e);
        }
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
