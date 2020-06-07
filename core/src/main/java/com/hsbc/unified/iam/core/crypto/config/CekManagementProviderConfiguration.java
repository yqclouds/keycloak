package com.hsbc.unified.iam.core.crypto.config;

import com.hsbc.unified.iam.core.crypto.CekManagementProvider;
import com.hsbc.unified.iam.core.crypto.RsaCekManagementProvider;
import org.keycloak.jose.jwe.JWEConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class CekManagementProviderConfiguration {
    @Bean
    public CekManagementProvider rsaesOaepCekManagementProvider() {
        return new RsaCekManagementProvider(JWEConstants.RSA_OAEP);
    }

    @Bean
    public CekManagementProvider rsaesPkcs1CekManagementProvider() {
        return new RsaCekManagementProvider(JWEConstants.RSA1_5);
    }

    @Bean
    public Map<String, CekManagementProvider> cekManagementProviders() {
        Map<String, CekManagementProvider> results = new HashMap<>();
        results.put(JWEConstants.RSA_OAEP, rsaesOaepCekManagementProvider());
        results.put(JWEConstants.RSA1_5, rsaesPkcs1CekManagementProvider());
        return results;
    }
}
