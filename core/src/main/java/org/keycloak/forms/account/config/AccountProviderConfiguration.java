package org.keycloak.forms.account.config;

import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.account.freemarker.FreeMarkerAccountProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class AccountProviderConfiguration {
    @Bean
    public AccountProvider freeMarkerAccountProvider() {
        return new FreeMarkerAccountProvider();
    }

    @Bean
    public Map<String, AccountProvider> accountProviders() {
        Map<String, AccountProvider> results = new HashMap<>();
        results.put("freemarker", freeMarkerAccountProvider());
        return results;
    }
}
