package com.hsbc.unified.iam.core.crypto.config;

import com.hsbc.unified.iam.core.crypto.Algorithm;
import com.hsbc.unified.iam.core.crypto.AsymmetricSignatureProvider;
import com.hsbc.unified.iam.core.crypto.ECDSASignatureProvider;
import com.hsbc.unified.iam.core.crypto.MacSecretSignatureProvider;
import com.hsbc.unified.iam.core.crypto.SignatureProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class SignatureProviderConfiguration {
    @Bean
    public SignatureProvider HS384SignatureProvider() {
        return new MacSecretSignatureProvider(Algorithm.HS384);
    }

    @Bean
    public SignatureProvider PS512SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.PS512);
    }

    @Bean
    public SignatureProvider HS512SignatureProvider() {
        return new MacSecretSignatureProvider(Algorithm.HS512);
    }

    @Bean
    public SignatureProvider PS256SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.PS256);
    }

    @Bean
    public SignatureProvider ES512SignatureProvider() {
        return new ECDSASignatureProvider(Algorithm.ES512);
    }

    @Bean
    public SignatureProvider ES256SignatureProvider() {
        return new ECDSASignatureProvider(Algorithm.ES256);
    }

    @Bean
    public SignatureProvider RS512SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.RS512);
    }

    @Bean
    public SignatureProvider RS384SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.RS384);
    }

    @Bean
    public SignatureProvider RS256SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.RS256);
    }

    @Bean
    public SignatureProvider PS384SignatureProvider() {
        return new AsymmetricSignatureProvider(Algorithm.PS384);
    }

    @Bean
    public SignatureProvider ES384SignatureProvider() {
        return new ECDSASignatureProvider(Algorithm.ES384);
    }

    @Bean
    public SignatureProvider HS256SignatureProvider() {
        return new MacSecretSignatureProvider(Algorithm.HS256);
    }

    @Bean
    public Map<String, SignatureProvider> signatureProviders() {
        Map<String, SignatureProvider> results = new HashMap<>();
        results.put(Algorithm.HS384, HS384SignatureProvider());
        results.put(Algorithm.PS512, PS512SignatureProvider());
        results.put(Algorithm.HS512, HS512SignatureProvider());
        results.put(Algorithm.PS256, PS256SignatureProvider());
        results.put(Algorithm.ES512, ES512SignatureProvider());
        results.put(Algorithm.ES256, ES256SignatureProvider());
        results.put(Algorithm.RS512, RS512SignatureProvider());
        results.put(Algorithm.RS384, RS384SignatureProvider());
        results.put(Algorithm.RS256, RS256SignatureProvider());
        results.put(Algorithm.PS384, PS384SignatureProvider());
        results.put(Algorithm.ES384, ES384SignatureProvider());
        results.put(Algorithm.HS256, HS256SignatureProvider());
        return results;
    }
}
