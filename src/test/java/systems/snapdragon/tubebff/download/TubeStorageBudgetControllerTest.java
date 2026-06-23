package systems.snapdragon.tubebff.download;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.tubebff.config.SecurityConfig;
import systems.snapdragon.tubebff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The ADMIN storage-budget surface gating (reactive @WebFluxTest): setting a user's
 * download storage budget is ADMIN | SUPERADMIN only (mounted under
 * {@code /bff/tube/admin/**}). FORBIDDEN for a plain ROLE_TUBE user / plain USER; the
 * target user's budget is set with the brand server-derived from the admin's token.
 */
@WebFluxTest(controllers = TubeStorageBudgetController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class TubeStorageBudgetControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean StorageUsageService usage;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asTubeUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_TUBE")));
    }

    private static StorageUsage usageRow(long budget) {
        return new StorageUsage("default", "bob", 0L, budget, Instant.now());
    }

    private static final String BODY = "{\"userSubject\":\"bob\",\"budgetBytes\":5000}";

    @Test
    void setBudget_allowedForAdmin() {
        when(usage.setBudget(eq("bob"), any(), anyLong())).thenReturn(Mono.just(usageRow(5000L)));
        asAdmin().post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.budgetBytes").isEqualTo(5000)
                .jsonPath("$.userSubject").isEqualTo("bob");
    }

    @Test
    void setBudget_allowedForSuperadmin() {
        when(usage.setBudget(eq("bob"), any(), anyLong())).thenReturn(Mono.just(usageRow(5000L)));
        asSuperadmin().post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk();
    }

    @Test
    void setBudget_forbiddenForPlainTubeUser() {
        asTubeUser().post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void setBudget_400WhenUserSubjectMissing() {
        asAdmin().post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"budgetBytes\":5000}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void setBudget_400WhenBudgetNegative() {
        asAdmin().post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"userSubject\":\"bob\",\"budgetBytes\":-1}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void setBudget_unauthenticated_is401() {
        web.post().uri("/bff/tube/admin/storage-budget")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isUnauthorized();
    }
}
