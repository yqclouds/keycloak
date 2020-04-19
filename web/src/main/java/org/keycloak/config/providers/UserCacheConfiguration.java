package org.keycloak.config.providers;

import org.keycloak.models.cache.infinispan.InfinispanUserCacheProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserCacheConfiguration {
    @Bean
    public InfinispanUserCacheProviderFactory infinispanUserCacheProviderFactory() {
        return new InfinispanUserCacheProviderFactory();
    }
}
