package systems.snapdragon.tubebff.google;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code tube_google_link} — the per-(brand,user) Google OAuth
 * connection (schema in Liquibase {@code db/changelog/005-tube-google-link.xml}).
 *
 * <p>Refactored (2026-06-18 data-access standard) from hand-written
 * {@code DatabaseClient} raw SQL to delegate to {@link TubeGoogleLinkR2dbcRepository}
 * (Spring Data R2DBC). Owner-scoped, fail-closed, single-domain; the never-hard-delete /
 * soft-revoke audit semantics are UNCHANGED.
 */
@Repository
public class TubeGoogleLinkRepository {

    private final TubeGoogleLinkR2dbcRepository repo;

    public TubeGoogleLinkRepository(TubeGoogleLinkR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The LIVE Google connection for an owner in their brand ({@code revoked_at IS NULL}),
     *  or empty. Owner+domain scoped (fail-closed; no cross-brand match). */
    public Mono<TubeGoogleLink> findLive(String domain, String userSubject) {
        return repo.findFirstByDomainAndUserSubjectAndRevokedAtIsNullOrderByConnectedAtDescIdAsc(
                domain, userSubject);
    }

    /**
     * Insert a fresh LIVE connection (app-generated id) stamped with the owner's brand +
     * subject and the AES-256-GCM refresh-token ciphertext. The caller is expected to have
     * soft-revoked any prior live row first.
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

    /** Soft-revoke the live connection for an owner in their brand (stamps
     *  {@code revoked_at}); the row is RETAINED = audit. Returns rows-updated. */
    public Mono<Long> softRevoke(String domain, String userSubject) {
        return repo.softRevoke(domain, userSubject);
    }

    /** Mark the live connection as needing re-auth (a refresh exchange failed). Owner+domain
     *  scoped. */
    public Mono<Long> markReauthRequired(String domain, String userSubject) {
        return repo.markReauthRequired(domain, userSubject);
    }
}
