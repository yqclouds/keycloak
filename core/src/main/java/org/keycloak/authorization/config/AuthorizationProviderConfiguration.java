package org.keycloak.authorization.config;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.models.RealmModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class AuthorizationProviderConfiguration {
    @Bean
    @Scope("prototype")
    public AuthorizationProvider authorizationProvider(RealmModel realmModel) {
        return new AuthorizationProvider(realmModel);
    }
}
