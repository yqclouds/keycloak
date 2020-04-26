package org.keycloak.config.providers;

import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginFormsConfiguration {
    @Bean
    public FreeMarkerLoginFormsProviderFactory freeMarkerLoginFormsProviderFactory() {
        return new FreeMarkerLoginFormsProviderFactory();
    }
}
