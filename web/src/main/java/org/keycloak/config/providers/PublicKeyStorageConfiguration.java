package org.keycloak.config.providers;

import org.keycloak.keys.infinispan.InfinispanPublicKeyStorageProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PublicKeyStorageConfiguration {
    @Bean
    public InfinispanPublicKeyStorageProviderFactory infinispanPublicKeyStorageProviderFactory() {
        return new InfinispanPublicKeyStorageProviderFactory();
    }
}
