package org.keycloak.config.providers;

import org.keycloak.models.jpa.JpaUserProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserConfiguration {
    @Bean
    public JpaUserProviderFactory jpaUserProviderFactory() {
        return new JpaUserProviderFactory();
    }
}
