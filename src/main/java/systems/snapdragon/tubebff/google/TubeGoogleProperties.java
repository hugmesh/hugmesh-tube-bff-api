package systems.snapdragon.tubebff.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Base64;

/**
 * Bound configuration for the Google OAuth (youtube.readonly) connect + the at-rest
 * encryption of the crown-jewel refresh token. Bound from {@code tube.google.*} (env:
 * {@code TUBE_GOOGLE_*}) and REGISTERED via {@code @EnableConfigurationProperties} on
 * {@link TubeGoogleConfig} so the Spring context actually starts.
 *
 * <p><b>Secret provenance (ESO/Vault — NO secrets in git).</b> Every sensitive value is
 * an ESO-projected env var sourced from Vault; the repo + the deployment manifest carry
 * ONLY references/placeholders:
 * <ul>
 *   <li>{@code clientId} / {@code clientSecret} / {@code redirectUri} — the dedicated
 *       Google OAuth <b>Web</b> client (its own creds, NOT the Casdoor sign-in client) in
 *       Vault {@code secret/<brand>/tube-google} -> ESO -> {@code TUBE_GOOGLE_CLIENT_ID}
 *       etc. {@code access_type=offline&prompt=consent} on the consent URL is what yields
 *       a REFRESH TOKEN;</li>
 *   <li>{@code dek} — the per-service Data Encryption Key (base64 of EXACTLY 32 bytes =
 *       AES-256) in Vault {@code secret/<brand>/tube-token-dek} -> ESO ->
 *       {@code TUBE_GOOGLE_DEK}. {@link TokenCipher} AEAD-encrypts the refresh token with
 *       it so the cleartext never lands in a DB row;</li>
 *   <li>{@code stateHmacKey} — the HMAC-SHA256 key (base64, &gt;=16 bytes) that signs the
 *       OAuth CSRF {@code state} ({@link GoogleConnectState}); ESO ->
 *       {@code TUBE_GOOGLE_STATE_HMAC_KEY}.</li>
 * </ul>
 *
 * <p><b>Fail-closed key validation.</b> {@link #decodeDek()} requires EXACTLY 32 bytes
 * (an undersized/oversized DEK is a misconfiguration that would weaken the AEAD — throw,
 * never silently pad/truncate) and {@link #decodeStateHmacKey()} requires &gt;=16 bytes.
 * A blank/unset key throws too, so a context wired without the secrets cannot serve the
 * connect endpoints with a degraded cipher.
 */
@ConfigurationProperties(prefix = "tube.google")
public class TubeGoogleProperties {

    /** The dedicated Google OAuth Web client id (ESO {@code secret/<brand>/tube-google}). */
    private String clientId;
    /** The dedicated Google OAuth Web client secret (ESO; NEVER in git). */
    private String clientSecret;
    /** The OAuth redirect URI registered on the Web client (Google redirects the user
     *  here with {@code code} + the signed {@code state}). */
    private String redirectUri;
    /** Base64 of the 32-byte AES-256 DEK (ESO {@code secret/<brand>/tube-token-dek}). */
    private String dek;
    /** Base64 of the HMAC-SHA256 key (&gt;=16 bytes) signing the OAuth state. */
    private String stateHmacKey;

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

    public String getDek() { return dek; }
    public void setDek(String dek) { this.dek = dek; }

    public String getStateHmacKey() { return stateHmacKey; }
    public void setStateHmacKey(String stateHmacKey) { this.stateHmacKey = stateHmacKey; }

    /**
     * Decode the configured DEK, requiring EXACTLY 32 bytes (AES-256). FAIL-CLOSED: a
     * blank/missing/wrong-length key throws {@link IllegalStateException} rather than
     * silently producing a weaker key — the refresh-token AEAD must never run with a
     * misconfigured DEK.
     */
    public byte[] decodeDek() {
        byte[] key = decodeBase64(dek, "tube.google.dek");
        if (key.length != 32) {
            throw new IllegalStateException(
                    "tube.google.dek must decode to exactly 32 bytes (AES-256); got " + key.length);
        }
        return key;
    }

    /**
     * Decode the configured state HMAC key, requiring &gt;=16 bytes. FAIL-CLOSED on a
     * blank/missing/too-short key.
     */
    public byte[] decodeStateHmacKey() {
        byte[] key = decodeBase64(stateHmacKey, "tube.google.state-hmac-key");
        if (key.length < 16) {
            throw new IllegalStateException(
                    "tube.google.state-hmac-key must decode to at least 16 bytes; got " + key.length);
        }
        return key;
    }

    private static byte[] decodeBase64(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required (ESO-projected from Vault) but was blank");
        }
        try {
            return Base64.getDecoder().decode(value.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(name + " is not valid base64", e);
        }
    }
}
