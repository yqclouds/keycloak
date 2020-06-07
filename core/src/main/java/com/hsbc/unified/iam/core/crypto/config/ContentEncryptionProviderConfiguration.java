package com.hsbc.unified.iam.core.crypto.config;

import com.hsbc.unified.iam.core.crypto.AesCbcHmacShaContentEncryptionProvider;
import com.hsbc.unified.iam.core.crypto.AesGcmContentEncryptionProvider;
import org.keycloak.crypto.ContentEncryptionProvider;
import org.keycloak.jose.jwe.JWEConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class ContentEncryptionProviderConfiguration {
    @Bean
    public ContentEncryptionProvider aesCbcHmacShaContentEncryptionProvider() {
        return new AesCbcHmacShaContentEncryptionProvider(JWEConstants.A128CBC_HS256);
    }

    @Bean
    public ContentEncryptionProvider aesGcmContentEncryptionProvider() {
        return new AesGcmContentEncryptionProvider(JWEConstants.A128GCM);
    }

    @Bean
    public Map<String, ContentEncryptionProvider> contentEncryptionProviders() {
        Map<String, ContentEncryptionProvider> results = new HashMap<>();
        results.put(JWEConstants.A128CBC_HS256, aesCbcHmacShaContentEncryptionProvider());
        results.put(JWEConstants.A128GCM, aesGcmContentEncryptionProvider());
        return results;
    }
}
