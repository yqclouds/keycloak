package org.keycloak.config.providers;

import org.keycloak.authorization.DefaultAuthorizationProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorizationConfiguration {
    @Bean
    public DefaultAuthorizationProviderFactory defaultAuthorizationProviderFactory() {
        return new DefaultAuthorizationProviderFactory();
    }
}
