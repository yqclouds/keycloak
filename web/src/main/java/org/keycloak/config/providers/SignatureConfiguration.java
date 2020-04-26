package org.keycloak.config.providers;

import org.keycloak.crypto.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SignatureConfiguration {
    @Bean
    public HS384SignatureProviderFactory hs384SignatureProviderFactory() {
        return new HS384SignatureProviderFactory();
    }

    @Bean
    public ES256SignatureProviderFactory es256SignatureProviderFactory() {
        return new ES256SignatureProviderFactory();
    }

    @Bean
    public HS512SignatureProviderFactory hs512SignatureProviderFactory() {
        return new HS512SignatureProviderFactory();
    }

    @Bean
    public ES384SignatureProviderFactory es384SignatureProviderFactory() {
        return new ES384SignatureProviderFactory();
    }

    @Bean
    public RS512SignatureProviderFactory rs512SignatureProviderFactory() {
        return new RS512SignatureProviderFactory();
    }

    @Bean
    public PS384SignatureProviderFactory ps384SignatureProviderFactory() {
        return new PS384SignatureProviderFactory();
    }

    @Bean
    public ES512SignatureProviderFactory es512SignatureProviderFactory() {
        return new ES512SignatureProviderFactory();
    }

    @Bean
    public PS512SignatureProviderFactory ps512SignatureProviderFactory() {
        return new PS512SignatureProviderFactory();
    }

    @Bean
    public RS384SignatureProviderFactory rs384SignatureProviderFactory() {
        return new RS384SignatureProviderFactory();
    }
}
