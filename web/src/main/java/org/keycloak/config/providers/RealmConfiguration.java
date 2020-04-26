package org.keycloak.config.providers;

import org.keycloak.models.jpa.JpaRealmProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RealmConfiguration {
    @Bean
    public JpaRealmProviderFactory jpaRealmProviderFactory() {
        return new JpaRealmProviderFactory();
    }
}
