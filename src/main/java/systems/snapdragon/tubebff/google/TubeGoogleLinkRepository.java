package systems.snapdragon.tubebff.google;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code tube_google_link} — the per-(brand,user) Google OAuth
 * connection (schema in Liquibase {@code db/changelog/005-tube-google-link.xml}). Follows
 * the PR2 {@code TubeAccessRepository} conventions: app-generated UUID ids (portable
 * across Postgres + the H2 slice store) and the reactive
 * {@code DatabaseClient.sql(...).bind().map().first()} shape.
 *
 * <p><b>Owner-scoped, fail-closed, single-domain.</b> Every read/write keys on BOTH
 * {@code domain} AND {@code user_subject}. A personal Google connect is ALWAYS
 * single-domain — there is NO SUPERADMIN null-domain bypass here (unlike the
 * {@code tube_access} governance reads): the {@code domain} predicate is ALWAYS present,
 * so a row is matched only within its own brand+owner. The service derives the domain
 * fail-closed (an unresolved issuer denies), so a blank/null domain never reaches here.
 *
 * <p>The connection is NEVER hard-deleted — a disconnect soft-revokes (stamps
 * {@code revoked_at}); the LIVE connection is the one with {@code revoked_at IS NULL}.
 */
@Repository
public class TubeGoogleLinkRepository {

    private final DatabaseClient db;

    public TubeGoogleLinkRepository(DatabaseClient db) {
        this.db = db;
    }

    private static final String COLS =
            "id, domain, user_subject, google_sub, google_email, refresh_token_ciphertext, "
            + "dek_id, scopes, connected_at, reauth_required, revoked_at";

    private static TubeGoogleLink map(Row row, RowMetadata meta) {
        Boolean reauth = row.get("reauth_required", Boolean.class);
        return new TubeGoogleLink(
                row.get("id", String.class),
                row.get("domain", String.class),
                row.get("user_subject", String.class),
                row.get("google_sub", String.class),
                row.get("google_email", String.class),
                row.get("refresh_token_ciphertext", String.class),
                row.get("dek_id", String.class),
                row.get("scopes", String.class),
                instant(row.get("connected_at", OffsetDateTime.class)),
                Boolean.TRUE.equals(reauth),
                instant(row.get("revoked_at", OffsetDateTime.class)));
    }

    /** The LIVE Google connection for an owner in their brand ({@code revoked_at IS NULL}),
     *  or empty. Owner+domain scoped (fail-closed; no cross-brand match). */
    public Mono<TubeGoogleLink> findLive(String domain, String userSubject) {
        return db.sql("SELECT " + COLS + " FROM tube_google_link "
                        + "WHERE domain = :domain AND user_subject = :user AND revoked_at IS NULL "
                        + "ORDER BY connected_at DESC, id")
                .bind("domain", domain).bind("user", userSubject)
                .map(TubeGoogleLinkRepository::map).first();
    }

    /**
     * Insert a fresh LIVE connection (app-generated id) stamped with the owner's brand +
     * subject and the AES-256-GCM refresh-token ciphertext. The caller (service) is
     * expected to have soft-revoked any prior live row first; the partial-unique index
     * (PG) is the race backstop.
     */
    public Mono<TubeGoogleLink> insert(String domain, String userSubject, String googleSub,
                                       String googleEmail, String refreshTokenCiphertext,
                                       String dekId, String scopes) {
        String id = UUID.randomUUID().toString();
        DatabaseClient.GenericExecuteSpec spec = db.sql(
                        "INSERT INTO tube_google_link "
                        + "(id, domain, user_subject, google_sub, google_email, "
                        + " refresh_token_ciphertext, dek_id, scopes, connected_at, "
                        + " reauth_required, revoked_at) "
                        + "VALUES (:id, :domain, :user, :gsub, :gemail, :ct, :dek, :scopes, "
                        + " now(), false, NULL)")
                .bind("id", id)
                .bind("domain", domain)
                .bind("user", userSubject)
                .bind("ct", refreshTokenCiphertext);
        spec = bindNullable(spec, "gsub", googleSub);
        spec = bindNullable(spec, "gemail", googleEmail);
        spec = bindNullable(spec, "dek", dekId);
        spec = bindNullable(spec, "scopes", scopes);
        return spec.fetch().rowsUpdated()
                .thenReturn(new TubeGoogleLink(id, domain, userSubject, googleSub, googleEmail,
                        refreshTokenCiphertext, dekId, scopes, Instant.now(), false, null));
    }

    /** Soft-revoke the live connection for an owner in their brand (stamps
     *  {@code revoked_at}); the row is RETAINED = audit. Returns rows-updated. */
    public Mono<Long> softRevoke(String domain, String userSubject) {
        return db.sql("UPDATE tube_google_link SET revoked_at = now() "
                        + "WHERE domain = :domain AND user_subject = :user AND revoked_at IS NULL")
                .bind("domain", domain).bind("user", userSubject)
                .fetch().rowsUpdated();
    }

    /** Mark the live connection as needing re-auth (a refresh exchange failed) — the UI
     *  prompts a re-connect and the sync loop STOPS. Owner+domain scoped. */
    public Mono<Long> markReauthRequired(String domain, String userSubject) {
        return db.sql("UPDATE tube_google_link SET reauth_required = true "
                        + "WHERE domain = :domain AND user_subject = :user AND revoked_at IS NULL")
                .bind("domain", domain).bind("user", userSubject)
                .fetch().rowsUpdated();
    }

    private static DatabaseClient.GenericExecuteSpec bindNullable(
            DatabaseClient.GenericExecuteSpec spec, String name, String value) {
        return value == null ? spec.bindNull(name, String.class) : spec.bind(name, value);
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
