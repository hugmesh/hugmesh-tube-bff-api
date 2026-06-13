package systems.snapdragon.tubebff.google;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM AEAD for the crown-jewel Google refresh token at rest. The refresh token
 * is stored ONLY as the ciphertext this produces — there is NO plaintext column on
 * {@code tube_google_link}.
 *
 * <p><b>Construction.</b> {@code AES/GCM/NoPadding}, a FRESH 12-byte
 * {@link SecureRandom} IV per encrypt (the GCM nonce — reuse with the same key is
 * catastrophic, so it is never fixed/derived), a 128-bit authentication tag, and the
 * 256-bit per-service DEK from {@link TubeGoogleProperties#decodeDek()} (ESO
 * {@code secret/<brand>/tube-token-dek}). The wire format stored in the DB column is
 * {@code base64(iv || ciphertext||tag)} — the IV is prepended (it is not secret, only
 * unique) so decrypt is self-contained.
 *
 * <p><b>Authentication.</b> GCM is authenticated: a tampered ciphertext (or one
 * decrypted with the WRONG DEK) fails the tag check and {@link #decrypt} throws — it
 * never returns attacker-influenced plaintext. A missing/short DEK fails closed at
 * construction-time decode ({@link TubeGoogleProperties#decodeDek()} throws).
 */
@Component
public class TokenCipher {

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_LEN = 12;          // 96-bit GCM nonce (the recommended size)
    private static final int TAG_BITS = 128;       // 128-bit authentication tag

    private final SecureRandom random = new SecureRandom();
    private final byte[] dek;                       // exactly 32 bytes (validated at decode)

    public TokenCipher(TubeGoogleProperties props) {
        this.dek = props.decodeDek();               // fail-closed: throws unless EXACTLY 32 bytes
    }

    /**
     * AEAD-encrypt {@code plaintext} (the Google refresh token) and return
     * {@code base64(iv || ct || tag)} — the value stored in
     * {@code tube_google_link.refresh_token_ciphertext}. A fresh random IV is generated
     * each call, so encrypting the same token twice yields different ciphertexts.
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext to encrypt must not be null");
        }
        try {
            byte[] iv = new byte[IV_LEN];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] out = ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
            return Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("refresh-token encryption failed", e);
        }
    }

    /**
     * Decrypt a {@code base64(iv || ct || tag)} blob back to the refresh token. Throws
     * {@link IllegalStateException} if the blob is malformed, the tag fails (tampered
     * ciphertext) or the DEK is wrong — never returns unauthenticated plaintext.
     */
    public String decrypt(String ciphertextB64) {
        if (ciphertextB64 == null || ciphertextB64.isBlank()) {
            throw new IllegalStateException("ciphertext to decrypt must not be blank");
        }
        try {
            byte[] all = Base64.getDecoder().decode(ciphertextB64.trim());
            if (all.length <= IV_LEN) {
                throw new IllegalStateException("ciphertext too short to contain an IV + tag");
            }
            byte[] iv = new byte[IV_LEN];
            System.arraycopy(all, 0, iv, 0, IV_LEN);
            byte[] ct = new byte[all.length - IV_LEN];
            System.arraycopy(all, IV_LEN, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // AEAD tag failure (tamper / wrong DEK) or a malformed blob — fail closed.
            throw new IllegalStateException("refresh-token decryption failed (tampered or wrong key)", e);
        }
    }

    private SecretKeySpec key() {
        return new SecretKeySpec(dek, "AES");
    }
}
