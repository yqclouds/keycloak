package org.keycloak.config.providers;

import org.keycloak.events.jpa.JpaEventStoreProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EventStoreConfiguration {
    @Bean
    public JpaEventStoreProviderFactory jpaEventStoreProviderFactory() {
        return new JpaEventStoreProviderFactory();
    }
}
