package systems.snapdragon.tubebff.google;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for the {@code tube_google_link} per-(brand, user) Google OAuth
 * connection record.
 *
 * <p>Schema: Liquibase {@code db/changelog/005-tube-google-link.xml}. Refactored
 * (2026-06-18 data-access standard) from hand-written {@code DatabaseClient} raw SQL to
 * delegate to {@link TubeGoogleLinkR2dbcRepository} (derived live-connection finder +
 * constant-{@code @Query} partial UPDATEs). Owner-scoped, fail-closed, single-domain;
 * never-hard-delete / soft-revoke audit semantics unchanged.
 *
 * @see TubeGoogleLinkR2dbcRepository
 * @see TubeGoogleLink
 */
@Repository
public class TubeGoogleLinkRepository {

    private final TubeGoogleLinkR2dbcRepository repo;

    public TubeGoogleLinkRepository(TubeGoogleLinkR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * The live Google connection for an owner in their brand ({@code revoked_at IS NULL}),
     * or empty if none exists. Owner + domain scoped (fail-closed; no cross-brand match).
     *
     * @param domain      the brand
     * @param userSubject the Casdoor subject of the owner
     * @return a {@code Mono} emitting the live {@link TubeGoogleLink}, or empty
     */
    public Mono<TubeGoogleLink> findLive(String domain, String userSubject) {
        return repo.findFirstByDomainAndUserSubjectAndRevokedAtIsNullOrderByConnectedAtDescIdAsc(
                domain, userSubject);
    }

    /**
     * Insert a fresh live connection row with an app-generated UUID id, stamped with the
     * owner's brand and subject and the AES-256-GCM refresh-token ciphertext. The caller
     * must soft-revoke any prior live row before calling this to avoid duplicate live rows.
     *
     * @param domain                  the brand
     * @param userSubject             the Casdoor subject of the owner
     * @param googleSub               the Google account subject (optional)
     * @param googleEmail             the Google account email (display-only)
     * @param refreshTokenCiphertext  the AES-256-GCM ciphertext of the refresh token
     * @param dekId                   the DEK version identifier
     * @param scopes                  the granted OAuth scope string
     * @return a {@code Mono} emitting the newly inserted {@link TubeGoogleLink}
     */
    public Mono<TubeGoogleLink> insert(String domain, String userSubject, String googleSub,
                                       String googleEmail, String refreshTokenCiphertext,
                                       String dekId, String scopes) {
        Instant connectedAt = Instant.now();
        // The id is DB-generated ((gen_random_uuid())::text DEFAULT, changelog 008): the
        // INSERT omits it and RETURNING id hands back the generated id, which we render into
        // the returned row (every other field unchanged from the former app-minted insert).
        return repo.insertReturningId(domain, userSubject, googleSub, googleEmail,
                        refreshTokenCiphertext, dekId, scopes, connectedAt)
                .map(id -> new TubeGoogleLink(id, domain, userSubject, googleSub, googleEmail,
                        refreshTokenCiphertext, dekId, scopes, connectedAt, false, null));
    }

    /**
     * Soft-revoke the live connection for an owner in their brand by stamping
     * {@code revoked_at = now()}. The row is retained for audit; never hard-deleted.
     *
     * @param domain      the brand
     * @param userSubject the Casdoor subject of the owner
     * @return a {@code Mono} emitting rows-updated (0 when already revoked)
     */
    public Mono<Long> softRevoke(String domain, String userSubject) {
        return repo.softRevoke(domain, userSubject);
    }

    /**
     * Mark the live connection as needing re-authentication. Called when a refresh-token
     * exchange fails at Google (token revoked or expired externally) so the UI prompts
     * a reconnect. Owner + domain scoped.
     *
     * @param domain      the brand
     * @param userSubject the Casdoor subject of the owner
     * @return a {@code Mono} emitting rows-updated
     */
    public Mono<Long> markReauthRequired(String domain, String userSubject) {
        return repo.markReauthRequired(domain, userSubject);
    }
}
