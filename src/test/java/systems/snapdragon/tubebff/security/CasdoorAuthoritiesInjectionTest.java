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

    // ── D8 MFA marker derivation — MFA_SATISFIED (fan-out parity w/ gateway) ──────
    // Emitted ONLY from the validated `mfa_satisfied_at` claim, behind
    // app.mfa.enabled, NON-role, never from roles/permissions; an explicit `now`
    // makes the freshness window deterministic.

    private static final long NOW = 1_750_000_000_000L;
    private static final long WINDOW = 600_000L;

    private static Jwt mfaJwt(String satisfiedAt) {
        return brandx().claim("mfa_satisfied_at", satisfiedAt).build();
    }

    private static List<String> names(List<GrantedAuthority> auth) {
        return auth.stream().map(GrantedAuthority::getAuthority).toList();
    }

    /** When app.mfa.enabled AND the BFF-written mfa_satisfied_at claim is FRESH, the
     *  converter adds the NON-role MFA_SATISFIED marker. */
    @Test
    void mfaEnabled_freshStamp_emitsMfaSatisfiedMarker_nonRole() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW - 60_000L)), BRANDX, on, NOW);
        assertThat(names(auth)).contains("MFA_SATISFIED");
        // It is a NON-role authority — never minted as ROLE_MFA_SATISFIED.
        assertThat(names(auth)).doesNotContain("ROLE_MFA_SATISFIED");
    }

    /** A STALE or FUTURE stamp produces NO marker (fail-closed freshness window). */
    @Test
    void mfaEnabled_staleOrFutureStamp_noMarker() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW - WINDOW - 1)), BRANDX, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW + 60_000L)), BRANDX, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
    }

    /** A BLANK/non-numeric stamp produces NO marker (fail-closed). */
    @Test
    void mfaEnabled_blankStamp_noMarker() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt("   "), BRANDX, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt("not-a-number"), BRANDX, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
    }

    /** Ships DARK: app.mfa.enabled=false (the default) => byte-identical legacy
     *  authority set, NO MFA_SATISFIED even with a fresh stamp; both the MfaConfig
     *  DISABLED path and the legacy no-MfaConfig overload are dark. */
    @Test
    void mfaDisabled_darkDefault_neverEmitsMarker_evenWithFreshStamp() {
        var auth = CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW)), BRANDX, CasdoorAuthorities.MfaConfig.DISABLED, NOW);
        assertThat(names(auth)).doesNotContain("MFA_SATISFIED");
        // The convenience overload (legacy, no MfaConfig) is also dark.
        assertThat(authorities(mfaJwt(Long.toString(NOW)))).doesNotContain("MFA_SATISFIED");
    }

    /** A forged permissions:["MFA_SATISFIED"] must NEVER inject the marker — it is
     *  dropped by the reserved-prefix guard; with NO valid claim the marker must not
     *  appear even when MFA is enabled. */
    @Test
    void forgedMfaSatisfiedPermission_isDropped_evenWhenMfaEnabled() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        Jwt jwt = brandx().claim(
                "permissions", List.of("MFA_SATISFIED", "mfa_satisfied", " MFA_SATISFIED ")).build();
        var auth = CasdoorAuthorities.authorities(jwt, BRANDX, on, NOW);
        assertThat(names(auth)).noneMatch(s -> s.toUpperCase().contains("MFA_SATISFIED"));
    }

    /** With BOTH a valid claim AND a forged permission, EXACTLY ONE MFA_SATISFIED
     *  survives — the converter's own (from the claim); the forged one is dropped. */
    @Test
    void forgedMfaSatisfiedPermission_doesNotSurvive_butValidClaimDoes() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        Jwt jwt = brandx()
                .claim("mfa_satisfied_at", Long.toString(NOW))
                .claim("permissions", List.of("MFA_SATISFIED")).build();
        var auth = CasdoorAuthorities.authorities(jwt, BRANDX, on, NOW);
        assertThat(names(auth)).filteredOn(s -> s.equals("MFA_SATISFIED")).hasSize(1);
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
