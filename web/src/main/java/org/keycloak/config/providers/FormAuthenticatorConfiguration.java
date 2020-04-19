package org.keycloak.config.providers;

import org.keycloak.authentication.forms.RegistrationPage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FormAuthenticatorConfiguration {
    @Bean
    public RegistrationPage registrationPage() {
        return new RegistrationPage();
    }
}
