package org.keycloak.config.providers;

import org.keycloak.credential.hash.Pbkdf2PasswordHashProviderFactory;
import org.keycloak.credential.hash.Pbkdf2Sha256PasswordHashProviderFactory;
import org.keycloak.credential.hash.Pbkdf2Sha512PasswordHashProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PasswordHashConfiguration {
    @Bean
    public Pbkdf2Sha256PasswordHashProviderFactory pbkdf2Sha256PasswordHashProviderFactory() {
        return new Pbkdf2Sha256PasswordHashProviderFactory();
    }

    @Bean
    public Pbkdf2Sha512PasswordHashProviderFactory pbkdf2Sha512PasswordHashProviderFactory() {
        return new Pbkdf2Sha512PasswordHashProviderFactory();
    }

    @Bean
    public Pbkdf2PasswordHashProviderFactory pbkdf2PasswordHashProviderFactory() {
        return new Pbkdf2PasswordHashProviderFactory();
    }
}
