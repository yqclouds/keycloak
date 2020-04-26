package org.keycloak.config.providers;

import org.keycloak.theme.DefaultThemeSelectorProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ThemeSelectorConfiguration {
    @Bean
    public DefaultThemeSelectorProviderFactory defaultThemeSelectorProviderFactory() {
        return new DefaultThemeSelectorProviderFactory();
    }
}
