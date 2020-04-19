package org.keycloak.config.providers;

import org.keycloak.crypto.SHA256HashProviderFactory;
import org.keycloak.crypto.SHA384HashProviderFactory;
import org.keycloak.crypto.SHA512HashProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HashConfiguration {
    @Bean
    public SHA256HashProviderFactory sha256HashProviderFactory() {
        return new SHA256HashProviderFactory();
    }

    @Bean
    public SHA384HashProviderFactory sha384HashProviderFactory() {
        return new SHA384HashProviderFactory();
    }

    @Bean
    public SHA512HashProviderFactory sha512HashProviderFactory() {
        return new SHA512HashProviderFactory();
    }
}
