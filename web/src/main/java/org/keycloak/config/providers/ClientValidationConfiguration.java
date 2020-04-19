package org.keycloak.config.providers;

import org.keycloak.validation.DefaultClientValidationProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientValidationConfiguration {
    @Bean
    public DefaultClientValidationProviderFactory defaultClientValidationProviderFactory() {
        return new DefaultClientValidationProviderFactory();
    }
}
