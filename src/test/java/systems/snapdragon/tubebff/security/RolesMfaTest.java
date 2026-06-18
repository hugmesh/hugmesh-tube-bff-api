package systems.snapdragon.tubebff.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * D8 MFA freshness unit coverage for {@link Roles#isMfaSatisfied(Jwt, long, long)} —
 * fan-out parity with the canonical snapdragon-gateway {@code RolesTest}. The
 * BFF-written top-level snake_case {@code mfa_satisfied_at} claim is the SOLE source
 * of the second-factor proof; every malformed input fails CLOSED and the method NEVER
 * throws. An explicit {@code now} keeps the freshness window deterministic.
 */
class RolesMfaTest {

    private static final long WINDOW = 600_000L; // 10m

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://casdoor.example");
    }

    private static Jwt mfaJwt(Object satisfiedAt) {
        return base().claim("mfa_satisfied_at", satisfiedAt).build();
    }

    private static Jwt jwtWith(Map<String, Object> claims) {
        Jwt.Builder b = base();
        claims.forEach(b::claim);
        return b.build();
    }

    @Test
    void isMfaSatisfied_freshStampString_withinWindow_true() {
        long now = 1_750_000_000_000L;
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 60_000L)), now, WINDOW)).isTrue();
        // Exactly at the window edge is still fresh (age == window).
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW)), now, WINDOW)).isTrue();
        // age == 0 (just stamped) is fresh.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now)), now, WINDOW)).isTrue();
    }

    @Test
    void isMfaSatisfied_staleStamp_pastWindow_false() {
        long now = 1_750_000_000_000L;
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW - 1)), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 3_600_000L)), now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_futureStamp_rejected() {
        long now = 1_750_000_000_000L;
        // A FUTURE stamp (age < 0) is rejected — clock-skew / forged-future defense.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 1)), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 3_600_000L)), now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_missingOrMalformed_failsClosed() {
        long now = 1_750_000_000_000L;
        // Claim absent.
        assertThat(Roles.isMfaSatisfied(jwtWith(Map.of("roles", List.of("admin"))), now, WINDOW)).isFalse();
        // Blank / non-numeric / non-positive.
        assertThat(Roles.isMfaSatisfied(mfaJwt("   "), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("not-a-number"), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("0"), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("-1"), now, WINDOW)).isFalse();
        // Null JWT.
        assertThat(Roles.isMfaSatisfied(null, now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_numericClaim_alsoTolerated() {
        long now = 1_750_000_000_000L;
        // Defensive: a JSON Number is parsed too (should not happen via Casdoor, costs nothing).
        assertThat(Roles.isMfaSatisfied(mfaJwt(now - 60_000L), now, WINDOW)).isTrue();
        assertThat(Roles.isMfaSatisfied(mfaJwt(now + 1L), now, WINDOW)).isFalse();   // future number rejected
    }
}
