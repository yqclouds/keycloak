package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanActionTokenStoreProviderFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ActionTokenStoreConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "keycloak", name = "enabled", havingValue = "true")
    public InfinispanActionTokenStoreProviderFactory infinispanActionTokenStoreProviderFactory() {
        return new InfinispanActionTokenStoreProviderFactory();
    }
}
