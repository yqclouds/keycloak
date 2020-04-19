package org.keycloak.config.providers;

import org.keycloak.executors.DefaultExecutorsProviderFactory;
import org.keycloak.executors.ExecutorsProviderFactory;
import org.keycloak.provider.ProviderFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class ExecutorsConfiguration {
    /**
     * @see org.keycloak.executors.ExecutorsProvider
     */
    @Bean
    public Map<String, ProviderFactory<?>> executorsProviderFactories() {
        Map<String, ProviderFactory<?>> results = new HashMap<>();
        results.put("default", executorsProviderFactory());
        return results;
    }

    @Bean
    @ConditionalOnProperty(prefix = "keycloak.executors.default", name = "enabled", havingValue = "true")
    public ExecutorsProviderFactory executorsProviderFactory() {
        return new DefaultExecutorsProviderFactory();
    }
}
