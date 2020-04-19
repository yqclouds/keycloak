package org.keycloak.config.providers;

import org.keycloak.models.cache.infinispan.authorization.InfinispanCacheStoreFactoryProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorizationCacheConfiguration {
    @Bean
    public InfinispanCacheStoreFactoryProviderFactory infinispanCacheStoreFactoryProviderFactory() {
        return new InfinispanCacheStoreFactoryProviderFactory();
    }
}
