package org.keycloak.config.providers;

import org.keycloak.keys.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyConfiguration {
    @Bean
    public JavaKeystoreKeyProviderFactory javaKeystoreKeyProviderFactory() {
        return new JavaKeystoreKeyProviderFactory();
    }

    @Bean
    public GeneratedHmacKeyProviderFactory generatedHmacKeyProviderFactory() {
        return new GeneratedHmacKeyProviderFactory();
    }

    @Bean
    public GeneratedAesKeyProviderFactory generatedAesKeyProviderFactory() {
        return new GeneratedAesKeyProviderFactory();
    }

    @Bean
    public GeneratedRsaKeyProviderFactory generatedRsaKeyProviderFactory() {
        return new GeneratedRsaKeyProviderFactory();
    }

    @Bean
    public GeneratedEcdsaKeyProviderFactory generatedEcdsaKeyProviderFactory() {
        return new GeneratedEcdsaKeyProviderFactory();
    }

    @Bean
    public ImportedRsaKeyProviderFactory importedRsaKeyProviderFactory() {
        return new ImportedRsaKeyProviderFactory();
    }
}
