package org.keycloak.config.providers;

import org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProviderFactory;
import org.keycloak.services.clientregistration.AdapterInstallationClientRegistrationProviderFactory;
import org.keycloak.services.clientregistration.DefaultClientRegistrationProviderFactory;
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientRegistrationConfiguration {
    @Bean
    public OIDCClientRegistrationProviderFactory oidcClientRegistrationProviderFactory() {
        return new OIDCClientRegistrationProviderFactory();
    }

    @Bean
    public EntityDescriptorClientRegistrationProviderFactory entityDescriptorClientRegistrationProviderFactory() {
        return new EntityDescriptorClientRegistrationProviderFactory();
    }

    @Bean
    public DefaultClientRegistrationProviderFactory defaultClientRegistrationProviderFactory() {
        return new DefaultClientRegistrationProviderFactory();
    }

    @Bean
    public AdapterInstallationClientRegistrationProviderFactory adapterInstallationClientRegistrationProviderFactory() {
        return new AdapterInstallationClientRegistrationProviderFactory();
    }
}
