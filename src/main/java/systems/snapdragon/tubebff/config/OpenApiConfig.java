package systems.snapdragon.tubebff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Minimal OpenAPI document metadata for the tube BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed client for the paired snapdragon-tube-ui (PR6) and the docs
 * pipeline key off these fields. A programmatic {@link OpenAPI} bean is used
 * (rather than the {@code @OpenAPIDefinition} annotation) so the metadata is plain
 * bean wiring — no annotation reflection scan, which keeps the GraalVM native
 * build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI tubeBffOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("snapdragon-tube-bff-api")
                        .version("0.1.0")
                        .description("Tube BFF API (/bff/tube/**) — the access governance plane "
                                + "for the LocalTube video optional service. PR2 owns the tube_access "
                                + "use/timeout/ban overlay (cloned from owncast_grant / wiki_access): "
                                + "DEFAULT-DENY may-use enforced at request time by TubeAccessGuard (an "
                                + "active use grant AND NOT an active ban, precedence ban>grant, SUPERADMIN "
                                + "exempt). Grant/timeout/ban/restore gated TUBE_GOVERN (admin|superadmin); "
                                + "list-all/history gated TUBE_MANAGE (superadmin). All surfaces are "
                                + "domain-scoped per multi-brand: a scoped ADMIN governs only own-brand "
                                + "users. The Google-connect/subs-sync, the yt-dlp downloader, and the "
                                + "per-domain content media serving (range/HLS) are SEPARATE components, "
                                + "not this BFF."));
    }
}
