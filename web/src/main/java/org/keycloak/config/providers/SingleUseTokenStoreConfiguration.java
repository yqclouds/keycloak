package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanSingleUseTokenStoreProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SingleUseTokenStoreConfiguration {
    @Bean
    public InfinispanSingleUseTokenStoreProviderFactory infinispanSingleUseTokenStoreProviderFactory() {
        return new InfinispanSingleUseTokenStoreProviderFactory();
    }
}
