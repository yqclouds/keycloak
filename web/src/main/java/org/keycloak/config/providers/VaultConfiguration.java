package org.keycloak.config.providers;

import org.keycloak.vault.FilesPlainTextVaultProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VaultConfiguration {
    @Bean
    public FilesPlainTextVaultProviderFactory filesPlainTextVaultProviderFactory() {
        return new FilesPlainTextVaultProviderFactory();
    }
}
