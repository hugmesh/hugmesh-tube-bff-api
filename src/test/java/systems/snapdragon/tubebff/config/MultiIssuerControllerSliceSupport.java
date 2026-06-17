package systems.snapdragon.tubebff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.snapdragon.tubebff.security.DomainRegistry;

/**
 * Wave-2 controller-slice scaffolding — builds a {@link WebTestClient} that drives the
 * REAL {@code @RestController} beans THROUGH the production
 * {@link SecurityConfig#filterChain} AND the production
 * {@link TenancyResourceServerConfig} per-brand resolver, with NO full Spring Boot
 * context and NO live Casdoor (each brand's JWKS/OIDC discovery is served by an
 * in-process {@code TestIssuer}). MIRRORS the reusable seam established by
 * snapdragon-gateway PR #34 ({@code SecuritySliceSupport}); it lives in the
 * {@code config} package for the same reason PR #7's {@code SecuritySliceSupport} does —
 * {@link SecurityConfig#filterChain} and
 * {@link TenancyResourceServerConfig#tenantAuthManagerResolver()} are package-private, so
 * the production chain can only be assembled from inside this package. A DISTINCT class
 * name from PR #7's helper keeps the two test-only seams from colliding when both branches
 * merge.
 *
 * <p><b>Why drive the controllers (not a synthetic echo controller).</b> PR #7's
 * multi-issuer slice proves the resolver emits the right authorities at the filter layer
 * (it routes a {@code whoami} echo). This wave goes one layer deeper: it binds
 * {@link systems.snapdragon.tubebff.media.TubeMediaController} /
 * {@link systems.snapdragon.tubebff.download.TubeStorageBudgetController} themselves, so
 * the assertions are at the HTTP boundary of the real controller — 401 unauthenticated,
 * 403 cross-brand / wrong-owner, 200 + the correct issuer-derived domain for the
 * authorized caller.
 *
 * <p><b>On the chain.</b> {@code SecurityConfig#filterChain} is the production
 * ({@code !dev & !test}) profile chain; its {@code commonRoutes(...)} role/path table is
 * byte-identical to the dev/test chain (only the SpringDoc spec gating differs, which the
 * controllers under test do not exercise). Invoking the method directly bypasses the
 * {@code @Profile} selection so the policy under test is exactly the deployed one.
 */
abstract class MultiIssuerControllerSliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} wired to the REAL multi-issuer resolver
     * for {@code registry}. A bearer minted by a {@code TestIssuer} whose issuer is in
     * {@code registry} authenticates and is stamped with the issuer-derived
     * {@code DOMAIN_<x>}; a bearer from an unlisted issuer 401s (fail-closed).
     *
     * @param registry    the issuer-&gt;domain registry (must be multi-issuer so the
     *                     resolver swap takes effect)
     * @param controllers the real @RestController instances under test
     */
    static WebTestClient sliceClient(DomainRegistry registry, Object... controllers) {
        return sliceClient(registry, new Object[0], controllers);
    }

    /**
     * As {@link #sliceClient(DomainRegistry, Object...)} but ALSO registers
     * {@code controllerAdvice} — the production {@code @RestControllerAdvice}
     * ({@code ApiExceptionHandler}) MUST be present so a controller's
     * {@code Mono.error(ApiException.forbidden(...))} renders as its carried 403/400
     * status (the deployed behaviour) rather than the bare-{@code bindToController} 500.
     * The existing {@code @WebFluxTest} slices get this via {@code @Import}; a
     * {@code bindToController} slice must register it explicitly.
     *
     * @param registry          the issuer-&gt;domain registry (must be multi-issuer)
     * @param controllerAdvice  the @RestControllerAdvice instances (e.g. ApiExceptionHandler)
     * @param controllers       the real @RestController instances under test
     */
    static WebTestClient sliceClient(DomainRegistry registry, Object[] controllerAdvice,
                                     Object... controllers) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                new TenancyResourceServerConfig(registry, "", "").tenantAuthManagerResolver();

        SecurityConfig config = new SecurityConfig(registry, provider(resolver));
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .controllerAdvice(controllerAdvice)
                .webFilter(securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} whose {@code getIfAvailable()} yields {@code value}
     *  (the method {@code SecurityConfig.resourceServer(...)} calls). */
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }
}
