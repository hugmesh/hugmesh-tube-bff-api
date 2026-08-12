package net.hugmesh.tubebff.download;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/tube/downloads}, {@code /bff/tube/internal/**},
 * and {@code /bff/tube/admin/storage-budget} HTTP boundaries.
 *
 * <p>All records carry {@code @JsonIgnoreProperties(ignoreUnknown = true)} for
 * forward-compatibility. The owner ({@code user_subject}) and brand ({@code domain}) are
 * NEVER read from a user request body — they are server-derived from the validated JWT (see
 * {@link DownloadJobService}). The admin budget request carries the TARGET user subject
 * (an admin acts ON another user, within their own brand which is server-derived).
 *
 * <h2>Nested types</h2>
 *
 * <pre>
 *   Job           — one tube_download_job row returned to its owner / a worker
 *   JobList       — list wrapper: { "jobs": [...] }
 *   ClaimRequest  — worker claim request (workerId, limit)
 *   ReportRequest — worker report request (jobId, workerId, result, bytes, contentPath, error)
 *   BudgetRequest — admin budget-set request (userSubject, budgetBytes)
 *   Usage         — tube_storage_usage row returned to an admin
 * </pre>
 *
 * @see TubeDownloadController
 * @see TubeDownloadWorkerController
 * @see TubeStorageBudgetController
 */
public final class TubeDownloadDto {

    private TubeDownloadDto() {}

    /**
     * A {@code tube_download_job} row as returned to its owner or a worker. All fields are
     * direct projections from {@link DownloadJob}; no secrets cross this boundary.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Job(String id, String domain, String userSubject, String channelId, String videoId,
                      String title, String state, String claimedBy, Instant claimedAt, int attempts,
                      String lastError, Long bytes, String contentPath, Instant createdAt, Instant updatedAt) {

        /**
         * Project a {@link DownloadJob} entity to its wire-shape DTO.
         *
         * @param j the entity to project
         * @return a new {@code Job} record with all fields copied
         */
        public static Job of(DownloadJob j) {
            return new Job(j.id(), j.domain(), j.userSubject(), j.channelId(), j.videoId(), j.title(),
                    j.state(), j.claimedBy(), j.claimedAt(), j.attempts(), j.lastError(), j.bytes(),
                    j.contentPath(), j.createdAt(), j.updatedAt());
        }
    }

    /**
     * List-response wrapper for {@code GET /downloads} and {@code POST /downloads}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record JobList(List<Job> jobs) {}

    // ── internal worker bodies ─────────────────────────────────────────────────

    /** {@code POST .../internal/download-jobs/claim} — a worker claims up to {@code limit}
     *  queued jobs under its {@code workerId}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ClaimRequest(
            @NotBlank(message = "workerId is required")
            @Size(max = 255, message = "workerId is too long")
            String workerId,
            @Min(value = 1, message = "limit must be at least 1")
            int limit) {}

    /** {@code POST .../internal/download-jobs/report} — a worker reports a job result. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ReportRequest(
            @NotBlank(message = "jobId is required")
            String jobId,
            @NotBlank(message = "workerId is required")
            @Size(max = 255, message = "workerId is too long")
            String workerId,
            @NotBlank(message = "result is required (done|failed|downloading)")
            String result,
            long bytes,
            @Size(max = 2048, message = "contentPath is too long")
            String contentPath,
            @Size(max = 2048, message = "error is too long")
            String error) {}

    // ── admin budget body ───────────────────────────────────────────────────────

    /** {@code POST .../admin/storage-budget} — an ADMIN sets a target user's budget cap. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BudgetRequest(
            @NotBlank(message = "userSubject is required")
            @Size(max = 400, message = "userSubject is too long")
            String userSubject,
            @Min(value = 0, message = "budgetBytes must be non-negative")
            long budgetBytes) {}

    /**
     * The {@code tube_storage_usage} row as returned after a budget set or a usage query.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Usage(String domain, String userSubject, long usedBytes, long budgetBytes,
                        Instant updatedAt) {

        /**
         * Project a {@link StorageUsage} entity to its wire-shape DTO.
         *
         * @param u the entity to project
         * @return a new {@code Usage} record with all fields copied
         */
        public static Usage of(StorageUsage u) {
            return new Usage(u.domain(), u.userSubject(), u.usedBytes(), u.budgetBytes(), u.updatedAt());
        }
    }
}
