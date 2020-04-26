package org.keycloak.config.providers;

import org.keycloak.locale.DefaultLocaleUpdaterProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LocaleUpdaterConfiguration {
    @Bean
    public DefaultLocaleUpdaterProviderFactory defaultLocaleUpdaterProviderFactory() {
        return new DefaultLocaleUpdaterProviderFactory();
    }
}
