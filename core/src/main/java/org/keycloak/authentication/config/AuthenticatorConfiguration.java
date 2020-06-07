package org.keycloak.authentication.config;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticator;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticatorFactory;
import org.keycloak.authentication.authenticators.challenge.BasicAuthAuthenticator;
import org.keycloak.authentication.authenticators.challenge.BasicAuthAuthenticatorFactory;
import org.keycloak.authentication.authenticators.challenge.BasicAuthOTPAuthenticator;
import org.keycloak.authentication.authenticators.challenge.BasicAuthOTPAuthenticatorFactory;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticatorFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class AuthenticatorConfiguration {
    @Bean
    public Map<String, ConfigurableAuthenticatorFactory> configurableAuthenticatorFactories() {
        Map<String, ConfigurableAuthenticatorFactory> results = new HashMap<>();
        results.put("basic-auth", basicAuthAuthenticatorFactory());
        results.put("basic-auth-otp", basicAuthOTPAuthenticatorFactory());
        results.put("client-secret", clientIdAndSecretAuthenticator());
        results.put("auth-conditional-otp-form", conditionalOtpFormAuthenticatorFactory());
        results.put("conditional-user-role", conditionalRoleAuthenticatorFactory());
        results.put("conditional-user-configured", conditionalUserConfiguredAuthenticatorFactory());
        results.put("auth-cookie", cookieAuthenticatorFactory());
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        return results;
    }

    @Bean
    public BasicAuthAuthenticatorFactory basicAuthAuthenticatorFactory() {
        return new BasicAuthAuthenticatorFactory();
    }

    @Bean
    public BasicAuthOTPAuthenticatorFactory basicAuthOTPAuthenticatorFactory() {
        return new BasicAuthOTPAuthenticatorFactory();
    }

    @Bean
    public ConditionalOtpFormAuthenticatorFactory conditionalOtpFormAuthenticatorFactory() {
        return new ConditionalOtpFormAuthenticatorFactory();
    }

    @Bean
    public ConditionalRoleAuthenticatorFactory conditionalRoleAuthenticatorFactory() {
        return new ConditionalRoleAuthenticatorFactory();
    }

    @Bean
    public ConditionalUserConfiguredAuthenticatorFactory conditionalUserConfiguredAuthenticatorFactory() {
        return new ConditionalUserConfiguredAuthenticatorFactory();
    }

    @Bean
    public CookieAuthenticatorFactory cookieAuthenticatorFactory() {
        return new CookieAuthenticatorFactory();
    }

    @Bean
    public Map<String, Authenticator> authenticators() {
        Map<String, Authenticator> results = new HashMap<>();
        results.put("basic-auth", basicAuthAuthenticator());
        results.put("basic-auth-otp", basicAuthOTPAuthenticator());
        results.put("auth-conditional-otp-form", conditionalOtpFormAuthenticator());
        results.put("conditional-user-role", conditionalRoleAuthenticator());
        results.put("conditional-user-configured", conditionalUserConfiguredAuthenticator());
        results.put("auth-cookie", cookieAuthenticator());
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        results.put("", null);
        return results;
    }

    @Bean
    public BasicAuthAuthenticator basicAuthAuthenticator() {
        return new BasicAuthAuthenticator();
    }

    @Bean
    public BasicAuthOTPAuthenticator basicAuthOTPAuthenticator() {
        return new BasicAuthOTPAuthenticator();
    }

    @Bean
    public ConditionalOtpFormAuthenticator conditionalOtpFormAuthenticator() {
        return new ConditionalOtpFormAuthenticator();
    }

    @Bean
    public ConditionalRoleAuthenticator conditionalRoleAuthenticator() {
        return new ConditionalRoleAuthenticator();
    }

    @Bean
    public ConditionalUserConfiguredAuthenticator conditionalUserConfiguredAuthenticator() {
        return new ConditionalUserConfiguredAuthenticator();
    }

    @Bean
    public CookieAuthenticator cookieAuthenticator() {
        return new CookieAuthenticator();
    }

    @Bean
    public Map<String, ClientAuthenticator> clientAuthenticators() {
        Map<String, ClientAuthenticator> results = new HashMap<>();
        results.put("client-secret", clientIdAndSecretAuthenticator());
        return results;
    }

    @Bean
    public ClientIdAndSecretAuthenticator clientIdAndSecretAuthenticator() {
        return new ClientIdAndSecretAuthenticator();
    }
}
