package org.keycloak.config.providers;

import org.keycloak.services.clientregistration.policy.impl.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientRegistrationPolicyConfiguration {
    @Bean
    public MaxClientsClientRegistrationPolicyFactory maxClientsClientRegistrationPolicyFactory() {
        return new MaxClientsClientRegistrationPolicyFactory();
    }

    @Bean
    public ScopeClientRegistrationPolicyFactory scopeClientRegistrationPolicyFactory() {
        return new ScopeClientRegistrationPolicyFactory();
    }

    @Bean
    public ClientDisabledClientRegistrationPolicyFactory clientDisabledClientRegistrationPolicyFactory() {
        return new ClientDisabledClientRegistrationPolicyFactory();
    }

    @Bean
    public ProtocolMappersClientRegistrationPolicyFactory protocolMappersClientRegistrationPolicyFactory() {
        return new ProtocolMappersClientRegistrationPolicyFactory();
    }

    @Bean
    public ClientScopesClientRegistrationPolicyFactory clientScopesClientRegistrationPolicyFactory() {
        return new ClientScopesClientRegistrationPolicyFactory();
    }

    @Bean
    public ConsentRequiredClientRegistrationPolicyFactory consentRequiredClientRegistrationPolicyFactory() {
        return new ConsentRequiredClientRegistrationPolicyFactory();
    }

    @Bean
    public TrustedHostClientRegistrationPolicyFactory trustedHostClientRegistrationPolicyFactory() {
        return new TrustedHostClientRegistrationPolicyFactory();
    }
}
