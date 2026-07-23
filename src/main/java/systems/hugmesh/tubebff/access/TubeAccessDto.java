package systems.hugmesh.tubebff.access;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/tube/.../access} HTTP boundary for the use
 * grant / timeout / ban overlay.
 *
 * <p>All records carry {@code @JsonIgnoreProperties(ignoreUnknown = true)} so the UI can
 * forward richer payloads without breaking future BFF versions. The acting principal's
 * {@code grantedBy} and {@code domain} are NEVER read from the request body — the service
 * stamps them from the validated JWT ({@code granted_by} = Casdoor subject;
 * {@code domain} = validated issuer) so a caller cannot act under another admin or forge
 * a cross-tenant scope.
 *
 * <h2>Nested types</h2>
 *
 * <pre>
 *   Access       — one tube_access row returned to a manage/audit reader
 *   AccessList   — list wrapper: { "access": [...] }
 *   GrantOrBan   — request body for /grant and /ban (permanent override)
 *   Timeout      — request body for /timeout (bounded ban with a TTL)
 * </pre>
 *
 * @see TubeAccessController
 * @see TubeAccess
 */
public final class TubeAccessDto {

    private TubeAccessDto() {}

    /**
     * A {@code tube_access} row as returned to a manage or audit reader. All fields are
     * direct projections from {@link TubeAccess}; no secrets cross this boundary.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Access(String id, String domain, String userSubject, String accessType,
                         String state, String grantedBySubject, String reason,
                         Instant createdAt, Instant expiresAt, Instant revokedAt) {

        /**
         * Project a {@link TubeAccess} entity to its wire-shape DTO.
         *
         * @param a the entity row to project
         * @return a new {@code Access} record with all fields copied
         */
        public static Access of(TubeAccess a) {
            return new Access(a.id(), a.domain(), a.userSubject(), a.accessType(), a.state(),
                    a.grantedBySubject(), a.reason(), a.createdAt(), a.expiresAt(), a.revokedAt());
        }
    }

    /**
     * List-response wrapper for {@code GET /superadmin/access} and
     * {@code GET /superadmin/access/{subject}/history}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AccessList(List<Access> access) {
        /** Defensive copy: prevents external mutation of the internal list. */
        public AccessList {
            access = List.copyOf(access);
        }
    }

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
