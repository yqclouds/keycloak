package org.keycloak.config.providers;

import org.keycloak.crypto.RsaesOaepCekManagementProviderFactory;
import org.keycloak.crypto.RsaesPkcs1CekManagementProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CekManagementConfiguration {
    @Bean
    public RsaesPkcs1CekManagementProviderFactory rsaesPkcs1CekManagementProviderFactory() {
        return new RsaesPkcs1CekManagementProviderFactory();
    }

    @Bean
    public RsaesOaepCekManagementProviderFactory rsaesOaepCekManagementProviderFactory() {
        return new RsaesOaepCekManagementProviderFactory();
    }
}
