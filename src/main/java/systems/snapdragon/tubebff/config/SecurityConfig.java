package systems.snapdragon.tubebff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import systems.snapdragon.tubebff.security.CasdoorAuthorities;
import systems.snapdragon.tubebff.security.DomainRegistry;
import systems.snapdragon.tubebff.security.PrincipalDomain;

/**
 * Casdoor-aware OAuth2 resource-server security for the tube BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates the {@code @PreAuthorize}
 * gates on the controllers. The JWT→authority mapping is delegated to the shared
 * {@link CasdoorAuthorities} converter — COPIED (logic) from the
 * adversarially-verified-safe snapdragon-gateway / owncast-bff so the BFF and the gateway
 * emit BYTE-IDENTICAL authorities, including the reserved-prefix injection guard on
 * {@code permissions} and exactly one issuer-derived {@code DOMAIN_<x>} tenant
 * authority.
 *
 * <p><b>Use-governance context.</b> This BFF owns the may-use governance plane
 * ({@code tube_access}), NOT the media plane: the downloaded content lives on a
 * per-domain content PVC served range/HLS through a SEPARATE be-gateway route + a
 * tube-media serving sidecar (PR5), and the Google-connect/subs-sync (PR3) + yt-dlp
 * downloader CronJob (PR4) are separate components. This filter chain is DEFENCE IN
 * DEPTH on top of the gateway route-access:
 * <ul>
 *   <li>{@code /bff/tube/superadmin/**} -> {@code hasRole('SUPERADMIN')} — the
 *       MANAGE-ALL surface (TUBE_MANAGE: list-all + history). Declared FIRST so the
 *       most-specific prefix wins.</li>
 *   <li>{@code /bff/tube/admin/**} -> {@code hasAnyRole('ADMIN','SUPERADMIN')} — the
 *       TUBE_GOVERN grant/timeout/ban/restore seam. Admins reach it via the
 *       converter's ROLE_ADMIN; SUPERADMIN reaches it via the role hierarchy edge.</li>
 *   <li>{@code /bff/tube/**} -> {@code .authenticated()} — the floor. The ROLE_TUBE
 *       route-access floor is enforced at the gateway; the converter adds ROLE_USER to
 *       every principal so {@code .authenticated()} proves authentication.</li>
 * </ul>
 *
 * <p><b>Default-deny use.</b> Use is GRANT-ONLY: the base {@code ROLE_TUBE} is the
 * route-access floor + the connect/view-own surface, but it does NOT by itself confer
 * USE — an admin's {@code tube_access} use grant is what lifts a user above the
 * default-deny floor. The exact decision — an active {@code tube_access} use grant AND
 * NOT an active ban, with SUPERADMIN exempt — is enforced programmatically by
 * {@code TubeAccessGuard}, because a static SpEL cannot consult the DB for a
 * per-principal grant or ban.
 *
 * <p><b>Domain-scope (multi-brand).</b> The tube access overrides are per-domain. A
 * scoped ADMIN of brand X governs ONLY brand X's users; the service/repo layers add a
 * {@code domain = :domain} predicate derived SERVER-SIDE from the validated issuer
 * ({@link PrincipalDomain}), with SUPERADMIN unscoped.
 *
 * <p><b>Multi-issuer is OPT-IN + backward-compatible.</b> When
 * {@code app.tenancy.issuers} carries per-brand issuer=domain pairs
 * ({@link TenancyResourceServerConfig} contributes a resolver AND the registry is
 * {@link DomainRegistry#isMultiIssuer()}), each trusted per-brand Casdoor validates
 * its own tokens (unknown {@code iss} → 401). Otherwise the resource server stays on
 * the existing single {@code o.jwt(...)} issuer-uri path — byte-for-byte unchanged.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
// SecurityConfig depends on DomainRegistry (the converter stamps the issuer-derived
// DOMAIN_<x>); PrincipalDomain is the controllers'/service's single domain-resolution
// bean. Importing both here means every @WebFluxTest slice that imports SecurityConfig
// gets them too — the slice context loads without each test re-declaring them.
@Import({DomainRegistry.class, PrincipalDomain.class})
public class SecurityConfig {

    /** Issuer→domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no issuer
     *  at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA floor (fan-out parity with snapdragon-gateway). Ships DARK: when
     *  {@code false} (the default) the converter emits the legacy byte-identical
     *  authority set and {@code MFA_SATISFIED} is NEVER produced. */
    private final boolean mfaEnabled;

    /** {@code 0 <= now - ts <= window} freshness window (millis) for the BFF-written
     *  {@code mfa_satisfied_at} claim. Default 10m. Only consulted when
     *  {@link #mfaEnabled}. */
    private final long mfaFreshnessWindow;

    @org.springframework.beans.factory.annotation.Autowired
    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindow) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindow = mfaFreshnessWindow;
    }

    /** Convenience constructor — MFA derivation OFF (the dark default with the
     *  standard 10m freshness window). Used by the security slice tests so their
     *  call sites stay byte-identical to the pre-D8 behaviour. */
    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver) {
        this(domainRegistry, tenantAuthManagerResolver, false, 600_000L);
    }

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. {@code /v3/api-docs} is the raw
     * OpenAPI JSON the platform ng-openapi-gen typed clients (the paired
     * snapdragon-tube-ui) + the docs pipeline fetch. Gated per profile (see the two
     * filter-chain beans): public under dev/test so {@code gen:fetch} can curl the
     * spec without a token, ROLE_ADMIN / SUPERADMIN everywhere else (prod) so the API
     * contract is never publicly reachable — matching the owncast-bff / wiki-bff template.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The
     * ONLY difference between the two profiles is how {@link #SPEC_PATHS} is gated,
     * so every other route lives here to keep the two chains in lockstep and make
     * it impossible to loosen a non-spec route by editing only one chain.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // The MANAGE-ALL surface — SUPERADMIN only (TUBE_MANAGE: list-all + history).
        // Declared BEFORE the admin + floor prefixes so the most-specific path matches first.
        ex.pathMatchers("/bff/tube/superadmin/**").hasRole("SUPERADMIN");
        // The INTERNAL download-worker seam (the future yt-dlp CronJob polls claim/report)
        // — ROLE_TUBE_WORKER (a service/mTLS principal) ONLY. Declared BEFORE the human
        // floor so the worker prefix is NOT swallowed by .authenticated(). Deliberately
        // OUTSIDE the human role hierarchy (no SUPERADMIN edge to TUBE_WORKER), so NO human
        // role can claim/complete another user's download job — a machine operation only.
        ex.pathMatchers("/bff/tube/internal/**").hasRole("TUBE_WORKER");
        // The TUBE_GOVERN grant/timeout/ban/restore seam + the admin storage-budget seam —
        // ADMIN (or the cross-domain SUPERADMIN super-role) end-to-end. Admins reach it via
        // the converter's ROLE_ADMIN; SUPERADMIN reaches it via the role hierarchy edge.
        ex.pathMatchers("/bff/tube/admin/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // The Google-connect + subscriptions surfaces (PR3) — the BASE service role
        // ROLE_TUBE is the route/connect floor here (the gateway also enforces it). The
        // FINER gate is the DEFAULT-DENY use overlay: TubeAccessGuard.assertCanUse(auth) is
        // called FIRST in every method (an active tube_access use grant AND not banned,
        // SUPERADMIN exempt), and the owner-scope (server-derived subject+brand) keeps a
        // user to THEIR OWN connection — neither of which a static SpEL can express.
        // Declared BEFORE the /bff/tube/** floor so this ROLE_TUBE rule wins for these.
        ex.pathMatchers("/bff/tube/google-connect/**").hasRole("TUBE");
        ex.pathMatchers("/bff/tube/subscriptions/**").hasRole("TUBE");
        // The rest of the tube surface — the ROLE_TUBE floor is enforced at the
        // gateway, so .authenticated() proves authentication here. The exact use
        // decision (an active grant AND NOT an active ban, SUPERADMIN exempt) is enforced
        // programmatically by TubeAccessGuard — NOT here, because a static SpEL
        // cannot consult the DB for a per-principal grant/ban.
        ex.pathMatchers("/bff/tube/**").authenticated();
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so
     * {@code gen:fetch} (ng-openapi-gen) and the docs pipeline can curl
     * {@code /v3/api-docs} locally without a Casdoor token. Activate with
     * {@code SPRING_PROFILES_ACTIVE=dev} (or the {@code test} profile the slice
     * tests use). Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::bffHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN (or the
     * cross-domain SUPERADMIN super-role) so the API contract is never publicly
     * reachable. Mirrors the owncast-bff / wiki-bff / user-bff profile split. Every
     * non-spec route is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::bffHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Reactive HTTP response-header hardening for a pure-JSON BFF resource server
     * (OWASP secure-headers / NIST 800-228 / ASVS V14.4). This BFF always sits
     * BEHIND the TLS-terminating snapdragon-gateway front door, which emits the full
     * browser-policy set (HSTS, the UI-shell CSP, Permissions-Policy, COOP/CORP) ONCE
     * for every brand so the 12 BFF configs can't drift; this method re-asserts only
     * the API-defensive minimum as defence-in-depth.
     *
     * <p><b>What this ADDS:</b> a no-document {@code Content-Security-Policy:
     * default-src 'none'; frame-ancestors 'none'} — the right CSP for a JSON API that
     * never serves HTML (locks any reflected/error body out of script/frame execution).
     *
     * <p><b>What this KEEPS (Spring reactive secure defaults — deliberately NOT
     * disabled):</b> {@code X-Content-Type-Options: nosniff},
     * {@code X-Frame-Options: DENY}, {@code Cache-Control: no-store...}, and
     * {@code Referrer-Policy} are all emitted by Spring's default header writers; this
     * method does not touch them so they remain in force.
     *
     * <p><b>What this deliberately OMITS:</b> HSTS (meaningless / misleading over the
     * plaintext intra-mesh hop to a BFF — it belongs ONLY at the gateway's TLS edge),
     * Permissions-Policy and the UI-shell CSP (no-document JSON API has no browsing
     * context to constrain). It also does NOT add {@code .cors(...)} — CORS stays
     * default-closed; this BFF is reached only via the gateway, never cross-origin.
     */
    private static void bffHeaders(ServerHttpSecurity.HeaderSpec h) {
        // Minimal API-CSP: a JSON BFF serves no HTML/script/frame — lock everything to 'none'.
        h.contentSecurityPolicy(csp ->
                csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"));
        // nosniff + X-Frame-Options DENY + Cache-Control + Referrer-Policy remain Spring
        // reactive secure defaults — intentionally left implicit (NOT disabled).
    }

    /**
     * Wire the OAuth2 resource server. Multi-issuer is OPT-IN: swap to the per-issuer
     * authentication-manager resolver ONLY when BOTH a resolver was contributed by
     * {@link TenancyResourceServerConfig} AND the registry is genuinely multi-issuer
     * (more than the single back-compat entry). Gating on {@code isMultiIssuer()} —
     * not merely {@code resolver != null} — keeps a single-issuer cluster on the
     * EXISTING issuer-uri {@code o.jwt(...)} decoder path even if the tenancy
     * conditional ever activates with just the lone back-compat issuer. In true
     * multi-brand mode each trusted per-brand Casdoor validates its own tokens
     * (unknown iss -> 401, fail-closed).
     */
    private void resourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately MINIMAL:
     * SUPERADMIN is a strict superset of admin/mod/user, but {@code ROLE_ADMIN} and
     * {@code ROLE_MOD} are documented SIBLINGS (no {@code ADMIN > MOD} edge). This bean
     * only smooths {@code @PreAuthorize} ergonomics + lets SUPERADMIN reach the
     * admin-gated govern + spec surfaces; the actual cross-surface authorization (and
     * the domain-scope, and the default-deny use decision) is enforced by the
     * service / guard layer.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    /**
     * Wire the {@link #roleHierarchy()} into REACTIVE method security so the
     * {@code @PreAuthorize("hasRole('ADMIN')")} gates honour {@code ROLE_SUPERADMIN >
     * ROLE_ADMIN} — i.e. the cross-domain SUPERADMIN reaches the ADMIN-only govern
     * methods without an explicit {@code ROLE_ADMIN}. (A bare {@code RoleHierarchy}
     * bean is NOT auto-applied to {@code @PreAuthorize} in the reactive
     * method-security path, so the expression handler is set explicitly.)
     */
    @Bean
    MethodSecurityExpressionHandler tubeMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        // Keep the default ROLE_ prefix explicit so hasRole('ADMIN') maps to ROLE_ADMIN.
        handler.setDefaultRolePrefix(new GrantedAuthorityDefaults("ROLE_").getRolePrefix());
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT → authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical —
     * three claim sources ({@code roles} → {@code ROLE_<UPPER>}, {@code permissions}
     * verbatim MINUS reserved-prefix injection, legacy {@code isAdmin} →
     * {@code ROLE_ADMIN}), a {@code ROLE_USER} floor, plus exactly one issuer-derived
     * {@code DOMAIN_<x>} authority (NON-role; {@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(
                domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindow));
    }
}
