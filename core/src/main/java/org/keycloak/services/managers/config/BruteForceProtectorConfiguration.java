package org.keycloak.services.managers.config;

import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.DefaultBruteForceProtector;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BruteForceProtectorConfiguration {
    @Bean
    public BruteForceProtector bruteForceProtector() {
        return new DefaultBruteForceProtector();
    }
}
