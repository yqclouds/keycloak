package org.keycloak.config.providers;

import org.keycloak.crypto.Aes128CbcHmacSha256ContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes128GcmContentEncryptionProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ContentEncryptionConfiguration {
    @Bean
    public Aes128GcmContentEncryptionProviderFactory aes128GcmContentEncryptionProviderFactory() {
        return new Aes128GcmContentEncryptionProviderFactory();
    }

    @Bean
    public Aes128CbcHmacSha256ContentEncryptionProviderFactory aes128CbcHmacSha256ContentEncryptionProviderFactory() {
        return new Aes128CbcHmacSha256ContentEncryptionProviderFactory();
    }
}
