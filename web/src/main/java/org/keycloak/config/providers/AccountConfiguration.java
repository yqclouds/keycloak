package org.keycloak.config.providers;

import org.keycloak.forms.account.AccountProviderFactory;
import org.keycloak.forms.account.freemarker.FreeMarkerAccountProviderFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AccountConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "keycloak.account", name = "enabled", havingValue = "true")
    public AccountProviderFactory freeMarkerAccountProviderFactory() {
        return new FreeMarkerAccountProviderFactory();
    }
}
