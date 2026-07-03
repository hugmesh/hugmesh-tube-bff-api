package systems.snapdragon.tubebff.google;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wiring for the Google-connect / subscriptions-sync feature (PR3). REGISTERS
 * {@link TubeGoogleProperties} via {@code @EnableConfigurationProperties} so the
 * {@code tube.google.*} binding participates in the context (without this the
 * {@code @ConfigurationProperties} class is just a POJO and nothing injects it), and
 * contributes the {@link WebClient} the {@link DefaultGoogleApiClient} impl uses to call
 * Google's token + Data API endpoints.
 *
 * <p>The {@code TokenCipher}, {@code GoogleConnectState}, {@code DefaultGoogleApiClient},
 * {@code GoogleConnectService}, {@code SubscriptionsSyncService} and the two controllers
 * are component-scanned ({@code @Component}/{@code @Service}/{@code @RestController}) so
 * the context starts with the full graph wired.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(TubeGoogleProperties.class)
public class TubeGoogleConfig {

    /** A plain reactive {@link WebClient} for Google's OAuth token endpoint + the
     *  YouTube Data API. No base URL — the impl uses absolute URIs so the endpoints are
     *  explicit + auditable. */
    @Bean
    WebClient tubeGoogleWebClient(WebClient.Builder builder) {
        return builder.build();
    }
}
