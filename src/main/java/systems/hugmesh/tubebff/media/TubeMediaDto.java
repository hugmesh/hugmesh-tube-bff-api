package systems.hugmesh.tubebff.media;

import java.time.Instant;

/**
 * Response DTOs for the media URL signing surface ({@code /bff/tube/media}).
 *
 * @see TubeMediaController
 * @see TubeMediaTokenService
 */
public final class TubeMediaDto {

    private TubeMediaDto() {}

    /**
     * Response from {@code GET /bff/tube/media/sign} — the fully signed media URL
     * plus its absolute expiry so the client can pre-emptively refresh before the
     * tube-media nginx sidecar rejects a stale token.
     *
     * @param url       the signed media URL ready for a {@code <video src>} or a
     *                  range request:
     *                  {@code /tube/content/<path>?sig=...&exp=...&sub=...&domain=...}
     * @param expiresAt the absolute expiry instant (UTC); 5 minutes from signing time.
     */
    public record SignedUrl(String url, Instant expiresAt) {}
}
