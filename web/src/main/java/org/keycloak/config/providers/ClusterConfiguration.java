package org.keycloak.config.providers;

import org.keycloak.cluster.infinispan.InfinispanClusterProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClusterConfiguration {
    @Bean
    public InfinispanClusterProviderFactory infinispanClusterProviderFactory() {
        return new InfinispanClusterProviderFactory();
    }
}
