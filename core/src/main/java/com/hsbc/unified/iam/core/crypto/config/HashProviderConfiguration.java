package com.hsbc.unified.iam.core.crypto.config;

import com.hsbc.unified.iam.core.crypto.HashProvider;
import com.hsbc.unified.iam.core.crypto.JavaAlgorithmHashProvider;
import com.hsbc.unified.iam.core.crypto.JavaAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class HashProviderConfiguration {
    @Bean
    public HashProvider SHA512HashProvider() {
        return new JavaAlgorithmHashProvider(JavaAlgorithm.SHA512);
    }

    @Bean
    public HashProvider SHA384HashProvider() {
        return new JavaAlgorithmHashProvider(JavaAlgorithm.SHA384);
    }

    @Bean
    public HashProvider SHA256HashProvider() {
        return new JavaAlgorithmHashProvider(JavaAlgorithm.SHA256);
    }

    @Bean
    public Map<String, HashProvider> hashProviders() {
        Map<String, HashProvider> results = new HashMap<>();
        results.put(JavaAlgorithm.SHA512, SHA512HashProvider());
        results.put(JavaAlgorithm.SHA384, SHA384HashProvider());
        results.put(JavaAlgorithm.SHA256, SHA256HashProvider());
        return results;
    }
}
