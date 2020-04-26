package org.keycloak.config.providers;

import org.keycloak.truststore.FileTruststoreProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TruststoreConfiguration {
    @Bean
    public FileTruststoreProviderFactory fileTruststoreProviderFactory() {
        return new FileTruststoreProviderFactory();
    }
}
