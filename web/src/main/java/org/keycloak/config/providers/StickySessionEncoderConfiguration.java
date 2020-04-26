package org.keycloak.config.providers;

import org.keycloak.models.sessions.infinispan.InfinispanStickySessionEncoderProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StickySessionEncoderConfiguration {
    @Bean
    public InfinispanStickySessionEncoderProviderFactory infinispanStickySessionEncoderProviderFactory() {
        return new InfinispanStickySessionEncoderProviderFactory();
    }
}
