package org.keycloak.config.providers;

import org.keycloak.authorization.config.UmaWellKnownProviderFactory;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WellKnownConfiguration {
    @Bean
    public OIDCWellKnownProviderFactory oidcWellKnownProviderFactory() {
        return new OIDCWellKnownProviderFactory();
    }

    @Bean
    public UmaWellKnownProviderFactory umaWellKnownProviderFactory() {
        return new UmaWellKnownProviderFactory();
    }
}
