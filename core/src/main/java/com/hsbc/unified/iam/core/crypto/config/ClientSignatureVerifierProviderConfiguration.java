package com.hsbc.unified.iam.core.crypto.config;

import com.hsbc.unified.iam.core.crypto.Algorithm;
import com.hsbc.unified.iam.core.crypto.AsymmetricClientSignatureVerifierProvider;
import com.hsbc.unified.iam.core.crypto.ClientSignatureVerifierProvider;
import com.hsbc.unified.iam.core.crypto.ECDSAClientSignatureVerifierProvider;
import com.hsbc.unified.iam.core.crypto.MacSecretClientSignatureVerifierProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class ClientSignatureVerifierProviderConfiguration {
    @Bean
    public ClientSignatureVerifierProvider HS512ClientSignatureVerifierProvider() {
        return new MacSecretClientSignatureVerifierProvider(Algorithm.HS512);
    }

    @Bean
    public ClientSignatureVerifierProvider PS256ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.PS256);
    }

    @Bean
    public ClientSignatureVerifierProvider RS384ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.RS384);
    }

    @Bean
    public ClientSignatureVerifierProvider RS256ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.RS256);
    }

    @Bean
    public ClientSignatureVerifierProvider PS512ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.PS512);
    }

    @Bean
    public ClientSignatureVerifierProvider ES256ClientSignatureVerifierProvider() {
        return new ECDSAClientSignatureVerifierProvider(Algorithm.ES256);
    }

    @Bean
    public ClientSignatureVerifierProvider ES512ClientSignatureVerifierProvider() {
        return new ECDSAClientSignatureVerifierProvider(Algorithm.ES512);
    }

    @Bean
    public ClientSignatureVerifierProvider ES384ClientSignatureVerifierProvider() {
        return new ECDSAClientSignatureVerifierProvider(Algorithm.ES384);
    }

    @Bean
    public ClientSignatureVerifierProvider RS512ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.RS512);
    }

    @Bean
    public ClientSignatureVerifierProvider PS384ClientSignatureVerifierProvider() {
        return new AsymmetricClientSignatureVerifierProvider(Algorithm.PS384);
    }

    @Bean
    public ClientSignatureVerifierProvider HS384ClientSignatureVerifierProvide() {
        return new MacSecretClientSignatureVerifierProvider(Algorithm.HS384);
    }

    @Bean
    public ClientSignatureVerifierProvider HS256ClientSignatureVerifierProvider() {
        return new MacSecretClientSignatureVerifierProvider(Algorithm.HS256);
    }

    @Bean
    public Map<String, ClientSignatureVerifierProvider> clientSignatureVerifierProviders() {
        Map<String, ClientSignatureVerifierProvider> results = new HashMap<>();
        results.put(Algorithm.HS512, HS512ClientSignatureVerifierProvider());
        results.put(Algorithm.PS256, PS256ClientSignatureVerifierProvider());
        results.put(Algorithm.RS384, RS384ClientSignatureVerifierProvider());
        results.put(Algorithm.RS256, RS256ClientSignatureVerifierProvider());
        results.put(Algorithm.PS512, PS512ClientSignatureVerifierProvider());
        results.put(Algorithm.ES256, ES256ClientSignatureVerifierProvider());
        results.put(Algorithm.ES512, ES512ClientSignatureVerifierProvider());
        results.put(Algorithm.ES384, ES384ClientSignatureVerifierProvider());
        results.put(Algorithm.RS512, RS512ClientSignatureVerifierProvider());
        results.put(Algorithm.PS384, PS384ClientSignatureVerifierProvider());
        results.put(Algorithm.HS384, HS384ClientSignatureVerifierProvide());
        results.put(Algorithm.HS256, HS256ClientSignatureVerifierProvider());
        return results;
    }
}
