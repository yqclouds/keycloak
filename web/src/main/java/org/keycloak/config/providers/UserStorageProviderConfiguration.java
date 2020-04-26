package org.keycloak.config.providers;

import org.keycloak.federation.sssd.SSSDFederationProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserStorageProviderConfiguration {
    @Bean
    public SSSDFederationProviderFactory sssdFederationProviderFactory() {
        return new SSSDFederationProviderFactory();
    }
}
