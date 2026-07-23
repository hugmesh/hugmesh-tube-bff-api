package systems.hugmesh.tubebff.config;


import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.commons.security.DomainRegistry;

/**
 * Shared scaffolding for the tube-BFF SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig#filterChain} (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 * COPIED from the adversarially-verified-safe hugmesh-gateway
 * {@code systems.hugmesh.gateway.config.SecuritySliceSupport}; only the package +
 * {@code DomainRegistry} import change — this repo's {@code SecurityConfig} constructor
 * has the identical {@code (DomainRegistry, ObjectProvider<...resolver...>)} shape.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern (see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}): a resource-server repo replicates the
 * slice by (1) constructing its own {@code SecurityConfig.filterChain} the same way
 * here, (2) supplying issuer-specific tokens via
 * {@link systems.hugmesh.tubebff.testsupport.TestIssuer}, and (3) asserting
 * authority emission / 401 fail-closed against {@code WebTestClient}.
 *
 * <p><b>Note on the chain.</b> {@code SecurityConfig#filterChain} is the production
 * ({@code !dev & !test}) profile chain — its {@code commonRoutes(...)} path/role table
 * is byte-identical to the dev/test chain; only the SpringDoc spec gating differs
 * (ADMIN/SUPERADMIN vs permitAll), which the slice does not exercise. Invoking the
 * method directly here bypasses the {@code @Profile} selection, so the policy under
 * test is exactly the deployed one.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .build();
    }

    /**
     * As {@link #sliceClient}, but ALSO registers the given {@code @RestControllerAdvice}
     * instances on the bound controller so a controller-body {@code Mono.error(ApiException)}
     * is rendered as its mapped status + {@code {"error":...}} body (otherwise an unhandled
     * {@code ApiException} surfaces as a raw 500 in a standalone {@code bindToController}
     * setup, which has no application {@code @ControllerAdvice}). Used by the media slice,
     * which must drive the controller BODY (the owner two-wall 403/400) through the real
     * security chain. The existing {@link #sliceClient} is left unchanged for the
     * gate-only slices that never reach a controller-body {@code ApiException}.
     */
    static WebTestClient sliceClientWithAdvice(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object[] controllerAdvice,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .controllerAdvice(controllerAdvice)
                .webFilter(securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
