package org.keycloak.config.providers;

import org.keycloak.models.jpa.session.JpaUserSessionPersisterProviderFactory;
import org.keycloak.models.session.DisabledUserSessionPersisterProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserSessionPersisterConfiguration {
    @Bean
    public JpaUserSessionPersisterProviderFactory jpaUserSessionPersisterProviderFactory() {
        return new JpaUserSessionPersisterProviderFactory();
    }

    @Bean
    public DisabledUserSessionPersisterProvider disabledUserSessionPersisterProvider() {
        return new DisabledUserSessionPersisterProvider();
    }
}
