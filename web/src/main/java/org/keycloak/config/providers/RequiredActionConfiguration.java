package org.keycloak.config.providers;

import org.keycloak.authentication.requiredactions.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RequiredActionConfiguration {
    @Bean
    public UpdateTotp updateTotp() {
        return new UpdateTotp();
    }

    @Bean
    public TermsAndConditions termsAndConditions() {
        return new TermsAndConditions();
    }

    @Bean
    public WebAuthnRegisterFactory webAuthnRegisterFactory() {
        return new WebAuthnRegisterFactory();
    }

    @Bean
    public UpdateUserLocaleAction updateUserLocaleAction() {
        return new UpdateUserLocaleAction();
    }

    @Bean
    public UpdatePassword updatePassword() {
        return new UpdatePassword();
    }

    @Bean
    public VerifyEmail verifyEmail() {
        return new VerifyEmail();
    }

    @Bean
    public WebAuthnPasswordlessRegisterFactory webAuthnPasswordlessRegisterFactory() {
        return new WebAuthnPasswordlessRegisterFactory();
    }

    @Bean
    public ConsoleUpdatePassword consoleUpdatePassword() {
        return new ConsoleUpdatePassword();
    }

    @Bean
    public UpdateProfile updateProfile() {
        return new UpdateProfile();
    }
}
