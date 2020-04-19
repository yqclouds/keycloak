package org.keycloak.config.providers;

import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CredentialConfiguration {
    @Bean
    public WebAuthnCredentialProviderFactory webAuthnCredentialProviderFactory() {
        return new WebAuthnCredentialProviderFactory();
    }

    @Bean
    public PasswordCredentialProviderFactory passwordCredentialProviderFactory() {
        return new PasswordCredentialProviderFactory();
    }

    @Bean
    public OTPCredentialProviderFactory otpCredentialProviderFactory() {
        return new OTPCredentialProviderFactory();
    }

    @Bean
    public WebAuthnPasswordlessCredentialProviderFactory webAuthnPasswordlessCredentialProviderFactory() {
        return new WebAuthnPasswordlessCredentialProviderFactory();
    }
}
