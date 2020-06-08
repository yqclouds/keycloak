package org.keycloak.protocol.config;

import org.keycloak.protocol.oidc.installation.KeycloakOIDCClientInstallation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientInstallationProviderConfiguration {
    @Bean
    public KeycloakOIDCClientInstallation keycloakOIDCClientInstallation() {
        return new KeycloakOIDCClientInstallation();
    }
}
