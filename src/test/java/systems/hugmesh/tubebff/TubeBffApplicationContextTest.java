package systems.hugmesh.tubebff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

/**
 * Context-load smoke test: the full Spring context boots under the {@code test}
 * profile. The {@link PostgresTestSupport} commons base auto-wires the runtime R2DBC +
 * Liquibase against a fresh, per-class Testcontainers Postgres database, so the
 * repositories + r2dbc-converters wire over a real (containerized) schema — the same
 * production Postgres engine, not an H2 emulation. The reactive JWT decoder is mocked so
 * no live Casdoor issuer is contacted. This proves the controller, service, repository,
 * the use access guard, and the security + native-hints config wire together.
 */
@SpringBootTest
@ActiveProfiles("test")
class TubeBffApplicationContextTest extends PostgresTestSupport {

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the
     *  oauth2 resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void contextLoads() {
        // success = the application context started with every bean wired.
    }
}
