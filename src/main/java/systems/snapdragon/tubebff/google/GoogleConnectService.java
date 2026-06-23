package systems.snapdragon.tubebff.google;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;

/**
 * The connect / callback / disconnect lifecycle of a user's Google (youtube.readonly)
 * link. This is SEPARATE from the Casdoor sign-in — the user explicitly grants this BFF
 * offline access to their YouTube subscriptions, and the crown-jewel REFRESH TOKEN is
 * AES-256-GCM-encrypted ({@link TokenCipher}) before it touches a DB row.
 *
 * <ul>
 *   <li>{@link #authorizeUrl} — build the Google consent URL with
 *       {@code access_type=offline&prompt=consent} (so a refresh token is issued) and a
 *       SIGNED {@code state} ({@link GoogleConnectState}) binding the acting subject +
 *       brand — the CSRF token AND the principal binder for the bearer-less callback.</li>
 *   <li>{@link #callback} — verify the signed state against the resolved principal,
 *       exchange the code, AEAD-encrypt the refresh token, and UPSERT the link (soft-revoke
 *       any prior live row first, then insert) stamped with the owner + brand.</li>
 *   <li>{@link #disconnect} — best-effort {@code google.revoke} of the stored refresh
 *       token, then soft-revoke the row (retained = audit).</li>
 * </ul>
 *
 * <p>Owner + domain are derived SERVER-SIDE ({@link PersonalOwner}) and FAIL CLOSED — a
 * personal connect is single-domain, with NO SUPERADMIN null-domain bypass.
 */
@Service
public class GoogleConnectService {

    private static final Logger log = LoggerFactory.getLogger(GoogleConnectService.class);

    private static final String AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
    /** The minimum scope: read the user's subscriptions. */
    private static final String SCOPE = "https://www.googleapis.com/auth/youtube.readonly";
    /** The DEK version stamped on a freshly-encrypted row (single-version for now). */
    private static final String DEK_ID = "v1";

    private final GoogleApiClient google;
    private final TokenCipher cipher;
    private final GoogleConnectState state;
    private final TubeGoogleLinkRepository links;
    private final TubeGoogleProperties props;
    private final PersonalOwner owner;

    public GoogleConnectService(GoogleApiClient google, TokenCipher cipher, GoogleConnectState state,
                                TubeGoogleLinkRepository links, TubeGoogleProperties props,
                                PersonalOwner owner) {
        this.google = google;
        this.cipher = cipher;
        this.state = state;
        this.links = links;
        this.props = props;
        this.owner = owner;
    }

    /**
     * The Google consent URL the UI redirects the user to. Carries the signed state that
     * binds the acting principal (subject + brand), so the bearer-less callback can
     * re-bind them.
     */
    public Mono<String> authorizeUrl(Authentication auth) {
        // Resolve the owner, then build the signed consent URL for the Google OAuth flow.
        return Mono.fromCallable(() -> owner.resolve(auth))
                .map(o -> buildAuthorizeUrl(o.subject(), o.domain()));
    }

    /**
     * Build the Google consent URL with a SIGNED state that binds the acting subject + brand.
     * The state is both the CSRF token and the principal binder for the bearer-less callback.
     */
    private String buildAuthorizeUrl(String subject, String domain) {
        String signedState = state.sign(subject, domain);
        return UriComponentsBuilder.fromUriString(AUTH_ENDPOINT)
                .queryParam("client_id", props.getClientId())
                .queryParam("redirect_uri", props.getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", SCOPE)
                .queryParam("access_type", "offline")   // -> a refresh token
                .queryParam("prompt", "consent")        // force re-consent so a refresh token is re-issued
                .queryParam("include_granted_scopes", "true")
                .queryParam("state", signedState)
                .build(true).toUriString();
    }

    /**
     * Handle Google's redirect: verify the signed state against the principal resolved
     * for THIS request, exchange the code, encrypt the refresh token, and persist the
     * link. The state is the source of the CSRF + principal binding — a tampered/expired/
     * cross-principal state is rejected BEFORE any code exchange.
     *
     * @param auth the request principal (when the callback CAN carry a bearer); the state
     *             is still verified against the resolved owner so the two must agree.
     */
    public Mono<TubeGoogleLink> callback(String code, String stateParam, Authentication auth) {
        // Resolve the owner, then verify the signed state and exchange the authorization code.
        return Mono.fromCallable(() -> owner.resolve(auth))
                .flatMap(o -> verifyAndExchange(o, code, stateParam));
    }

    /**
     * Verify the signed OAuth state against the resolved owner (CSRF + principal binding),
     * then exchange the authorization code and persist the encrypted link.
     */
    private Mono<TubeGoogleLink> verifyAndExchange(PersonalOwner.Owner o, String code,
                                                    String stateParam) {
        // CSRF + principal binding: the signed state must verify against the
        // subject+brand we resolved for this request. Reject (no code exchange)
        // on tamper/expiry/cross-principal.
        if (!state.verify(stateParam, o.subject(), o.domain())) {
            return Mono.error(ApiException.forbidden("invalid OAuth state"));
        }
        if (code == null || code.isBlank()) {
            return Mono.error(ApiException.badRequest("missing authorization code"));
        }
        // Exchange the code for tokens, then encrypt and persist the link.
        return google.exchangeCode(code)
                .flatMap(tok -> persist(o, tok));
    }

    private Mono<TubeGoogleLink> persist(PersonalOwner.Owner o, GoogleApiClient.TokenResponse tok) {
        if (tok.refreshToken() == null || tok.refreshToken().isBlank()) {
            // No refresh token (consent already granted without prompt=consent, or a
            // misconfigured client) — we can't do offline sync, so reject rather than
            // store a useless link.
            return Mono.error(ApiException.badGateway(
                    "google did not return a refresh token (re-consent required)"));
        }
        String ciphertext = cipher.encrypt(tok.refreshToken());   // crown jewel -> AEAD at rest
        String scopes = tok.scopes() == null ? SCOPE : tok.scopes();
        // A fresh connect supersedes any prior live link (re-consent): soft-revoke then insert.
        return links.softRevoke(o.domain(), o.subject())
                .then(links.insert(o.domain(), o.subject(), tok.googleSub(), tok.googleEmail(),
                        ciphertext, DEK_ID, scopes))
                .doOnNext(l -> log.info("[tube-google] connected link for {} in {} (id={})",
                        o.subject(), o.domain(), l.id()));
    }

    /**
     * Disconnect: best-effort revoke the stored refresh token at Google (decrypted only
     * in memory for the revoke call), then soft-revoke the row. Idempotent — a no-op when
     * there is no live link.
     */
    public Mono<Void> disconnect(Authentication auth) {
        return Mono.fromCallable(() -> owner.resolve(auth))
                .flatMap(o -> links.findLive(o.domain(), o.subject())
                        .flatMap(link -> revokeAtGoogle(link)
                                .then(links.softRevoke(o.domain(), o.subject())))
                        .doOnNext(n -> log.info("[tube-google] disconnected link for {} in {}",
                                o.subject(), o.domain()))
                        .then());
    }

    private Mono<Void> revokeAtGoogle(TubeGoogleLink link) {
        // Decrypt the refresh token in memory ONLY to revoke it at Google; never returned.
        String refresh;
        try {
            refresh = cipher.decrypt(link.refreshTokenCiphertext());
        } catch (RuntimeException e) {
            // A corrupt/undecryptable blob shouldn't block the soft-revoke.
            log.warn("[tube-google] could not decrypt refresh token to revoke (id={}): {}",
                    link.id(), e.getMessage());
            return Mono.empty();
        }
        return google.revoke(refresh).onErrorResume(e -> {
            log.warn("[tube-google] google.revoke failed (best-effort) id={}: {}",
                    link.id(), e.getMessage());
            return Mono.empty();
        });
    }
}
