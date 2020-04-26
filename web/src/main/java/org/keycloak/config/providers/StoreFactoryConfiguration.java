package org.keycloak.config.providers;

import org.keycloak.authorization.jpa.store.JPAAuthorizationStoreFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StoreFactoryConfiguration {
    @Bean
    public JPAAuthorizationStoreFactory jpaAuthorizationStoreFactory() {
        return new JPAAuthorizationStoreFactory();
    }
}
