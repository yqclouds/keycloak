package org.keycloak.config.providers;

import org.keycloak.models.cache.infinispan.InfinispanCacheRealmProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RealmCacheConfiguration {
    @Bean
    public InfinispanCacheRealmProviderFactory infinispanCacheRealmProviderFactory() {
        return new InfinispanCacheRealmProviderFactory();
    }
}
