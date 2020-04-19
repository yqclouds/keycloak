package org.keycloak.config.providers;

import org.keycloak.authentication.forms.RegistrationPassword;
import org.keycloak.authentication.forms.RegistrationProfile;
import org.keycloak.authentication.forms.RegistrationRecaptcha;
import org.keycloak.authentication.forms.RegistrationUserCreation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FormActionConfiguration {
    @Bean
    public RegistrationProfile registrationProfile() {
        return new RegistrationProfile();
    }

    @Bean
    public RegistrationUserCreation registrationUserCreation() {
        return new RegistrationUserCreation();
    }

    @Bean
    public RegistrationRecaptcha registrationRecaptcha() {
        return new RegistrationRecaptcha();
    }

    @Bean
    public RegistrationPassword registrationPassword() {
        return new RegistrationPassword();
    }
}
