package systems.snapdragon.tubebff.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CROSS-USER authority-injection regression for the canonical {@link CasdoorAuthorities}
 * reserved-prefix guard. A brand-X token carrying a FORGED {@code permissions} entry
 * must NEVER inject a {@code ROLE_*} super-role or a {@code DOMAIN_*} cross-tenant scope
 * — those authorities come ONLY from the converter's controlled logic (the roles claim
 * and the cryptographically-validated issuer). Without the guard such an entry would
 * escalate cross-domain.
 */
class CasdoorAuthoritiesInjectionTest {

    private static final DomainRegistry BRANDX = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    private static Jwt.Builder brandx() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").claim("iss", "https://id.brandx.example").issuer("https://id.brandx.example");
    }

    private List<String> authorities(Jwt jwt) {
        return CasdoorAuthorities.authorities(jwt, BRANDX).stream()
                .map(GrantedAuthority::getAuthority).toList();
    }

    /** A forged {@code permissions:["DOMAIN_brandy"]} must NOT inject a cross-tenant
     *  scope — the only DOMAIN_ authority is the issuer-derived DOMAIN_brandx. */
    @Test
    void forgedDomainPermission_isDropped_onlyIssuerDomainSurvives() {
        Jwt jwt = brandx().claim("permissions", List.of("DOMAIN_brandy")).build();
        List<String> auths = authorities(jwt);
        assertThat(auths).contains("DOMAIN_brandx");
        assertThat(auths).doesNotContain("DOMAIN_brandy");
        // Exactly one DOMAIN_ authority — the fail-closed authorities-overload relies on this.
        assertThat(auths.stream().filter(a -> a.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }

    /** A forged {@code permissions:["ROLE_SUPERADMIN"]} must NOT inject the super-role. */
    @Test
    void forgedRolePermission_isDropped() {
        Jwt jwt = brandx().claim("permissions", List.of("ROLE_SUPERADMIN")).build();
        assertThat(authorities(jwt)).doesNotContain("ROLE_SUPERADMIN");
    }

    /** The authorities-overload of {@code Roles.domainOf} fails CLOSED when MORE THAN
     *  ONE DOMAIN_ authority is present (an injection signature). The converter prevents
     *  that, but the overload refuses to be a spoofable side channel. */
    @Test
    void domainOfAuthorities_failsClosedOnMultipleDomains() {
        var authorities = List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("DOMAIN_brandx"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("DOMAIN_brandy"));
        assertThat(Roles.domainOf(authorities)).isNull();
    }
}
