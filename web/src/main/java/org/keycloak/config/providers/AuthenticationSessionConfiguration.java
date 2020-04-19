package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanAuthenticationSessionProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthenticationSessionConfiguration {
    @Bean
    public InfinispanAuthenticationSessionProviderFactory infinispanAuthenticationSessionProviderFactory() {
        return new InfinispanAuthenticationSessionProviderFactory();
    }
}
