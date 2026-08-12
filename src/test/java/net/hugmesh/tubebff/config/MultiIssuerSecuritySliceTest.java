package net.hugmesh.tubebff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.tubebff.testsupport.TestIssuer;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * MULTI-ISSUER security slice — the three keystones of the copyable pattern (see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}), exercised against THIS repo's REAL
 * {@link SecurityConfig#filterChain} + {@link TenancyResourceServerConfig} per-issuer
 * resolver on a {@link WebTestClient}. NO live Casdoor, NO network beyond loopback:
 * each brand's JWKS + OIDC discovery is served by an in-process {@link TestIssuer}.
 *
 * <table>
 *   <caption>What the slice asserts</caption>
 *   <tr><th>#</th><th>Scenario</th><th>Expectation</th><th>Category</th></tr>
 *   <tr><td>(a)</td><td>brand-X-issuer JWT</td>
 *       <td>authenticated + {@code DOMAIN_brandx} + role authorities</td>
 *       <td>USER-SITUATIONAL</td></tr>
 *   <tr><td>(b)</td><td>token from an UNLISTED issuer (well-formed, correctly signed)</td>
 *       <td>resolver returns empty → <b>401 fail-closed</b></td>
 *       <td>CROSS-USER DENY</td></tr>
 *   <tr><td>(c)</td><td>brand-Y JWT</td>
 *       <td>scoped to {@code DOMAIN_brandy}; NEVER {@code DOMAIN_brandx}</td>
 *       <td>CROSS-USER DENY</td></tr>
 * </table>
 *
 * <p>Plus the cheap fail-closed neighbours: a tampered signature and a garbage bearer
 * both 401.
 *
 * <p><b>Why fail-closed is load-bearing.</b> The per-issuer resolver's allowlist is
 * exactly {@link DomainRegistry#trustedIssuers()}; an {@code iss} outside that set
 * yields NO authentication manager, so 401 happens BEFORE any authority is emitted —
 * there is no default-accept fallback that could let an unlisted brand in. Scenario
 * (b) is the regression guard that keeps it that way.
 */
class MultiIssuerSecuritySliceTest extends SecuritySliceSupport {

    /** Minimal controller echoing the authenticated principal's authorities so the
     *  slice can assert exactly which authorities the resource server emitted. */
    @RestController
    static class AuthoritiesController {
        @GetMapping("/bff/tube/whoami")
        Mono<String> whoami() {
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication())
                    .map(Authentication::getAuthorities)
                    .map(auths -> auths.stream()
                            .map(GrantedAuthority::getAuthority)
                            .sorted()
                            .collect(Collectors.joining(",")));
        }
    }

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;          // a correctly-signed issuer NOT in the registry
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Registry trusts ONLY brandX + brandY. rogue is deliberately omitted.
        DomainRegistry registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode active")
                .isTrue();
        assertThat(registry.trustedIssuers())
                .containsExactlyInAnyOrder(brandX.issuerUri(), brandY.issuerUri());
        assertThat(registry.isTrusted(rogue.issuerUri()))
                .as("rogue issuer is NOT trusted")
                .isFalse();

        // Build the repo's real multi-issuer resolver the way the tenancy config
        // contributes it (back-compat issuer-uri/jwk-set-uri empty in this slice).
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(
                        new TenancyResourceServerConfig(registry, "", "", false, 600_000L));

        client = sliceClient(registry, provider(resolver), new AuthoritiesController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    private List<String> authoritiesFor(String token) {
        String body = client.get().uri("/bff/tube/whoami")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult().getResponseBody();
        return body == null || body.isEmpty() ? List.of() : List.of(body.split(","));
    }

    // ---- (a) trusted brand-X token -> authenticated + DOMAIN_brandx -----------------

    @Test
    void brandXToken_authenticates_withBrandxDomainAndRoles() {
        String token = brandX.mint("alice", List.of("tube", "admin"));
        List<String> authorities = authoritiesFor(token);

        assertThat(authorities)
                .contains("DOMAIN_brandx", "ROLE_USER", "ROLE_TUBE", "ROLE_ADMIN")
                .doesNotContain("DOMAIN_brandy", "DOMAIN_default");
    }

    // ---- (b) UNKNOWN issuer -> 401 fail-closed (the load-bearing assertion) ---------

    @Test
    void rogueIssuerToken_failsClosed_401_neverDefaultAccept() {
        // A correctly-signed, well-formed JWT — its ONLY sin is an unlisted iss.
        String token = rogue.mint("mallory", List.of("admin", "superadmin"));

        client.get().uri("/bff/tube/whoami")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ---- (c) brand-Y token is scoped to brand-Y, NEVER becomes brand-X --------------

    @Test
    void brandYToken_isScopedToBrandy_neverBrandx() {
        String token = brandY.mint("bob", List.of("tube"));
        List<String> authorities = authoritiesFor(token);

        assertThat(authorities)
                .contains("DOMAIN_brandy", "ROLE_USER", "ROLE_TUBE")
                .as("a brand-Y token can NEVER acquire brand-X's tenant scope")
                .doesNotContain("DOMAIN_brandx");
    }

    /** A brand-Y token presented as if it were brand-X's: the iss is cryptographically
     *  bound to brand-Y, so it can only ever resolve to brand-Y's manager. There is no
     *  way to make brand-Y's signature validate as brand-X. */
    @Test
    void brandYToken_cannotForgeBrandxAuthority_evenWithForgedRolesClaim() {
        // Even loading the token up with privileged roles does not cross the brand line.
        String token = brandY.mint("eve", List.of("superadmin", "admin"));
        List<String> authorities = authoritiesFor(token);

        assertThat(authorities)
                .contains("DOMAIN_brandy")
                .doesNotContain("DOMAIN_brandx");
    }

    // ---- cheap fail-closed neighbours -----------------------------------------------

    @Test
    void tamperedSignature_failsClosed_401() {
        String token = brandX.mint("alice", List.of("tube"));
        int lastDot = token.lastIndexOf('.');
        assertThat(lastDot).isGreaterThan(0);
        String header = token.substring(0, lastDot + 1);
        String signature = token.substring(lastDot + 1);
        // Reverse the signature segment so it can no longer verify against the key.
        // (A single-char flip can be a no-op when it only touches base64url padding
        // bits; reversing the whole 2048-bit RSA signature guarantees a mismatch.)
        String tampered = header + new StringBuilder(signature).reverse();
        assertThat(tampered).isNotEqualTo(token);

        client.get().uri("/bff/tube/whoami")
                .headers(h -> h.setBearerAuth(tampered))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void garbageBearer_failsClosed_401() {
        client.get().uri("/bff/tube/whoami")
                .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void noBearer_failsClosed_401() {
        client.get().uri("/bff/tube/whoami")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
