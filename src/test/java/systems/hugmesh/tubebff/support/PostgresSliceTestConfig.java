package systems.hugmesh.tubebff.support;

import liquibase.integration.spring.SpringLiquibase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.r2dbc.core.DatabaseClient;
import io.r2dbc.spi.ConnectionFactory;

import javax.sql.DataSource;

/**
 * Runs the PRODUCTION Liquibase changelog over the Testcontainers-Postgres database that
 * {@link systems.hugmesh.commons.testsupport.PostgresTestSupport} provisions, for the
 * {@code @DataR2dbcTest} repository/service SLICES that exercise the DB-generated-UUID-PK
 * tables (tube_access, tube_download_job, tube_google_link, tube_subscription).
 *
 * <p>WHY a dedicated config (vs. the full-context boot tests): a {@code @DataR2dbcTest}
 * slice auto-configures ONLY the reactive R2DBC stack — it does NOT load Spring Boot's
 * Liquibase auto-configuration. This {@code @TestConfiguration} re-adds a
 * {@link SpringLiquibase} bean (Liquibase has no R2DBC runner, so it uses a JDBC
 * datasource) pointed at the SAME container db that
 * {@code PostgresTestSupport.@DynamicPropertySource} published into
 * {@code spring.liquibase.*}. The reactive {@code ConnectionFactory} the slice wires from
 * {@code spring.r2dbc.*} resolves to the same db, so the repository runs against the real
 * Liquibase-applied schema — now including changelog 008 ({@code pgcrypto} +
 * {@code (gen_random_uuid())::text} DEFAULT) and {@code INSERT ... RETURNING id}, NEITHER
 * of which the old H2 PostgreSQL-compat store (the now-removed {@code TestDatabaseConfig})
 * could honour. That is exactly why the DB-generated-UUID-PK migration moves these slices
 * to Testcontainers-Postgres (adopting the mod-bff #36 / admin-bff #133 pattern).
 *
 * <p>This mirrors the former H2 {@code TestDatabaseConfig} bean shape (Liquibase + a
 * {@link DatabaseClient} + a {@link R2dbcEntityTemplate}) but targets the real Postgres
 * container instead of H2. The {@code DatabaseClient}/{@code R2dbcEntityTemplate} beans are
 * {@link ConditionalOnMissingBean} so the {@code @DataR2dbcTest} slice's own
 * auto-configured beans win when present; they are supplied only where a slice needs the
 * raw client (e.g. a direct re-read assertion) and the slice did not auto-wire one.
 */
@TestConfiguration(proxyBeanMethods = false)
public class PostgresSliceTestConfig {

    /** JDBC datasource at the container db published by PostgresTestSupport's
     *  {@code spring.liquibase.*} dynamic properties (Liquibase runs over JDBC). */
    @Bean
    public DataSource liquibaseDataSource(
            @Value("${spring.liquibase.url}") String url,
            @Value("${spring.liquibase.user}") String user,
            @Value("${spring.liquibase.password}") String password) {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.postgresql.Driver");
        ds.setUrl(url);
        ds.setUsername(user);
        ds.setPassword(password);
        return ds;
    }

    /** Apply the production changelog over the container db BEFORE the reactive
     *  repository runs (the slice depends on this bean transitively). */
    @Bean
    public SpringLiquibase liquibase(DataSource liquibaseDataSource) {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(liquibaseDataSource);
        lb.setChangeLog("classpath:db/changelog/db.changelog-master.xml");
        return lb;
    }

    /** The reactive client some slices use for direct re-read assertions — depends on the
     *  Liquibase bean so the schema is applied first. Only supplied if the slice did not
     *  auto-configure one. */
    @Bean
    @ConditionalOnMissingBean
    public DatabaseClient databaseClient(ConnectionFactory connectionFactory, SpringLiquibase liquibase) {
        return DatabaseClient.create(connectionFactory);
    }

    /** The {@link R2dbcEntityTemplate} the Spring Data R2DBC bootstrap needs; only supplied
     *  if the slice did not auto-configure one (depends on Liquibase so the schema exists). */
    @Bean
    @ConditionalOnMissingBean
    public R2dbcEntityTemplate r2dbcEntityTemplate(ConnectionFactory connectionFactory,
                                                   SpringLiquibase liquibase) {
        return new R2dbcEntityTemplate(connectionFactory);
    }
}
