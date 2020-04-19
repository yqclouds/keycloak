package org.keycloak.config.providers;

import org.keycloak.services.managers.DefaultBruteForceProtectorFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BruteForceProtectorConfiguration {
    @Bean
    public DefaultBruteForceProtectorFactory defaultBruteForceProtectorFactory() {
        return new DefaultBruteForceProtectorFactory();
    }
}
