package systems.snapdragon.tubebff.google;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.Roles;
import systems.snapdragon.commons.web.ApiException;

/**
 * Resolves the {@code (subject, domain)} key for a PERSONAL Google connect / subscriptions
 * read — the owner-scoped equivalent of {@code PrincipalDomain}, but DELIBERATELY without
 * the SUPERADMIN null-domain bypass.
 *
 * <p><b>Why no SUPERADMIN bypass (correction E).</b> A personal Google connection is
 * ALWAYS single-domain: it belongs to exactly one (brand, user). If we let a SUPERADMIN
 * resolve to a {@code null} domain (as the governance reads do), a SUPERADMIN's personal
 * read would match rows by {@code user_subject} ALONE across every brand — a cross-brand
 * leak. So here the domain is ALWAYS the concrete issuer-derived brand
 * ({@link Roles#domainOf}); a SUPERADMIN connecting their own Google account is scoped to
 * their own token's brand like anyone else.
 *
 * <p><b>Fail-closed.</b> A principal whose issuer the registry can't resolve (multi-brand
 * mode, unknown {@code iss} → {@code null} domain) or who carries no JWT subject is
 * REJECTED (403), never defaulted to a bypass — an unresolved domain denies rather than
 * matching rows across brands.
 */
@Component
public class PersonalOwner {

    private final DomainRegistry registry;

    public PersonalOwner(DomainRegistry registry) {
        this.registry = registry;
    }

    /**
     * Resolve the {@code (subject, domain)} key for this principal. A missing JWT subject,
     * an unauthenticated principal, or an unresolvable brand all throw a 403
     * {@link ApiException} (deliberately synchronous — callers wrap in
     * {@code Mono.fromCallable()} so the error surfaces as a failed {@code Mono}).
     *
     * @param auth the authenticated principal
     * @return the resolved {@link Owner} with a non-null, non-blank subject and domain
     * @throws ApiException (403) when the principal has no JWT, no subject, or an
     *         unresolvable brand — fail-closed, never defaults to a bypass
     */
    public Owner resolve(Authentication auth) {
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            throw ApiException.forbidden("a Google connection requires an authenticated user");
        }
        String subject = jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw ApiException.forbidden("the principal has no subject");
        }
        // Concrete issuer-derived brand — NEVER the SUPERADMIN null bypass for a personal
        // read. A non-resolvable issuer fails closed.
        String domain = Roles.domainOf(jwt, registry);
        if (domain == null || domain.isBlank()) {
            throw ApiException.forbidden("the principal's brand could not be resolved (fail-closed)");
        }
        return new Owner(subject, domain);
    }

    /** The {@code (subject, domain)} key a personal Google read/write scopes on. */
    public record Owner(String subject, String domain) {}
}
