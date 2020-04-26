package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanUserSessionProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserSessionConfiguration {
    @Bean
    public InfinispanUserSessionProviderFactory infinispanUserSessionProviderFactory() {
        return new InfinispanUserSessionProviderFactory();
    }
}
