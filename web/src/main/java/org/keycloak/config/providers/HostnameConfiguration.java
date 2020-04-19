package org.keycloak.config.providers;

import org.keycloak.url.DefaultHostnameProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HostnameConfiguration {
    @Bean
    public DefaultHostnameProviderFactory defaultHostnameProviderFactory() {
        return new DefaultHostnameProviderFactory();
    }
}
