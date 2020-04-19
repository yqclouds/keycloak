package org.keycloak.config.providers;

import org.keycloak.crypto.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientSignatureVerifierConfiguration {
    @Bean
    public RS256ClientSignatureVerifierProviderFactory rs256ClientSignatureVerifierProviderFactory() {
        return new RS256ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public HS384ClientSignatureVerifierProviderFactory hs384ClientSignatureVerifierProviderFactory() {
        return new HS384ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public ES512ClientSignatureVerifierProviderFactory es512ClientSignatureVerifierProviderFactory() {
        return new ES512ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public ES384ClientSignatureVerifierProviderFactory es384ClientSignatureVerifierProviderFactory() {
        return new ES384ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public PS256ClientSignatureVerifierProviderFactory ps256ClientSignatureVerifierProviderFactory() {
        return new PS256ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public RS512ClientSignatureVerifierProviderFactory rs512ClientSignatureVerifierProviderFactory() {
        return new RS512ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public ES256ClientSignatureVerifierProviderFactory es256ClientSignatureVerifierProviderFactory() {
        return new ES256ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public HS256ClientSignatureVerifierProviderFactory hs256ClientSignatureVerifierProviderFactory() {
        return new HS256ClientSignatureVerifierProviderFactory();
    }

    @Bean
    public RS384ClientSignatureVerifierProviderFactory rs384ClientSignatureVerifierProviderFactory() {
        return new RS384ClientSignatureVerifierProviderFactory();
    }
}
