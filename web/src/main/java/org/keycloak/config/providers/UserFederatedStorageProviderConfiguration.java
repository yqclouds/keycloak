package org.keycloak.config.providers;

import org.keycloak.federation.kerberos.KerberosFederationProviderFactory;
import org.keycloak.storage.jpa.JpaUserFederatedStorageProviderFactory;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserFederatedStorageProviderConfiguration {
    @Bean
    public JpaUserFederatedStorageProviderFactory jpaUserFederatedStorageProviderFactory() {
        return new JpaUserFederatedStorageProviderFactory();
    }

    @Bean
    public LDAPStorageProviderFactory ldapStorageProviderFactory() {
        return new LDAPStorageProviderFactory();
    }

    @Bean
    public KerberosFederationProviderFactory kerberosFederationProviderFactory() {
        return new KerberosFederationProviderFactory();
    }
}
