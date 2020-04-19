package org.keycloak.config.providers;

import org.keycloak.connections.jpa.updater.liquibase.lock.LiquibaseDBLockProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DBLockConfiguration {
    @Bean
    public LiquibaseDBLockProviderFactory liquibaseDBLockProviderFactory() {
        return new LiquibaseDBLockProviderFactory();
    }
}
