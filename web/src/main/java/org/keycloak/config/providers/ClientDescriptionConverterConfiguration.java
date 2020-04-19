package org.keycloak.config.providers;

import org.keycloak.exportimport.KeycloakClientDescriptionConverter;
import org.keycloak.protocol.oidc.OIDCClientDescriptionConverterFactory;
import org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientDescriptionConverterConfiguration {
    @Bean
    public OIDCClientDescriptionConverterFactory oidcClientDescriptionConverterFactory() {
        return new OIDCClientDescriptionConverterFactory();
    }

    @Bean
    public EntityDescriptorDescriptionConverter entityDescriptorDescriptionConverter() {
        return new EntityDescriptorDescriptionConverter();
    }

    @Bean
    public KeycloakClientDescriptionConverter keycloakClientDescriptionConverter() {
        return new KeycloakClientDescriptionConverter();
    }
}
