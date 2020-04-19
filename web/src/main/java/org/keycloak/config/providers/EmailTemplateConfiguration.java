package org.keycloak.config.providers;

import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EmailTemplateConfiguration {
    @Bean
    public FreeMarkerEmailTemplateProviderFactory freeMarkerEmailTemplateProviderFactory() {
        return new FreeMarkerEmailTemplateProviderFactory();
    }
}
