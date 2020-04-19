package org.keycloak.config.providers;

import org.keycloak.email.DefaultEmailSenderProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EmailSenderConfiguration {
    @Bean
    public DefaultEmailSenderProviderFactory defaultEmailSenderProviderFactory() {
        return new DefaultEmailSenderProviderFactory();
    }
}
