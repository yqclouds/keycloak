package org.keycloak.config.providers;

import org.keycloak.services.migration.DefaultMigrationProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MigrationConfiguration {
    @Bean
    public DefaultMigrationProviderFactory defaultMigrationProviderFactory() {
        return new DefaultMigrationProviderFactory();
    }
}
