package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanCodeToTokenStoreProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CodeToTokenStoreConfiguration {
    @Bean
    public InfinispanCodeToTokenStoreProviderFactory infinispanCodeToTokenStoreProviderFactory() {
        return new InfinispanCodeToTokenStoreProviderFactory();
    }
}
