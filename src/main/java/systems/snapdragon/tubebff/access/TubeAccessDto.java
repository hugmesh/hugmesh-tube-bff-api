package systems.snapdragon.tubebff.access;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/tube/.../access} HTTP boundary for the
 * use grant/timeout/ban overlay. Plain records
 * ({@code @JsonIgnoreProperties(ignoreUnknown)}). The acting principal's
 * {@code grantedBy} + {@code domain} are NEVER read from the body — the service stamps
 * them from the validated JWT (granted_by == Casdoor sub; domain == validated issuer) so
 * a caller cannot act under another admin or forge a cross-tenant scope.
 */
public final class TubeAccessDto {

    private TubeAccessDto() {}

    /** A {@code tube_access} row as returned to a manage/audit reader. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Access(String id, String domain, String userSubject, String accessType,
                         String state, String grantedBySubject, String reason,
                         Instant createdAt, Instant expiresAt, Instant revokedAt) {
        public static Access of(TubeAccess a) {
            return new Access(a.id(), a.domain(), a.userSubject(), a.accessType(), a.state(),
                    a.grantedBySubject(), a.reason(), a.createdAt(), a.expiresAt(), a.revokedAt());
        }
    }

    /** The list-response wrapper. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AccessList(List<Access> access) {}

    // ── request bodies ─────────────────────────────────────────────────

    /** {@code POST .../access/grant} and {@code .../access/ban} — a permanent override.
     *  {@code reason} is optional free text (audited). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GrantOrBan(
            @NotBlank(message = "userSubject is required")
            @Size(max = 400, message = "userSubject is too long")
            String userSubject,
            @Size(max = 1024, message = "reason is too long")
            String reason) {}

    /** {@code POST .../access/timeout} — a {@code banned} override with a FUTURE expiry.
     *  {@code ttlSeconds} drives the auto-restore instant; it must be positive. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Timeout(
            @NotBlank(message = "userSubject is required")
            @Size(max = 400, message = "userSubject is too long")
            String userSubject,
            @Positive(message = "ttlSeconds must be positive")
            long ttlSeconds,
            @Size(max = 1024, message = "reason is too long")
            String reason) {}
}
