package org.keycloak.config.providers;

import org.keycloak.events.email.EmailEventListenerProviderFactory;
import org.keycloak.events.log.JBossLoggingEventListenerProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EventListenerConfiguration {
    @Bean
    public EmailEventListenerProviderFactory emailEventListenerProviderFactory() {
        return new EmailEventListenerProviderFactory();
    }

    @Bean
    public JBossLoggingEventListenerProviderFactory jBossLoggingEventListenerProviderFactory() {
        return new JBossLoggingEventListenerProviderFactory();
    }
}
