package org.keycloak.config.providers;

import org.keycloak.locale.DefaultLocaleSelectorProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LocaleSelectorConfiguration {
    @Bean
    public DefaultLocaleSelectorProviderFactory defaultLocaleSelectorProviderFactory() {
        return new DefaultLocaleSelectorProviderFactory();
    }
}
