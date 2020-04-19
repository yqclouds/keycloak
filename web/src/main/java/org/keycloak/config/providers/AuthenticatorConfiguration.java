package org.keycloak.config.providers;

import org.keycloak.authentication.authenticators.broker.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.authentication.authenticators.challenge.BasicAuthAuthenticatorFactory;
import org.keycloak.authentication.authenticators.challenge.BasicAuthOTPAuthenticatorFactory;
import org.keycloak.authentication.authenticators.challenge.NoCookieFlowRedirectAuthenticatorFactory;
import org.keycloak.authentication.authenticators.cli.CliUsernamePasswordAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticatorFactory;
import org.keycloak.authentication.authenticators.console.ConsoleUsernamePasswordAuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.authentication.authenticators.resetcred.ResetOTP;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.protocol.docker.DockerAuthenticatorFactory;
import org.keycloak.protocol.saml.profile.ecp.authenticator.HttpBasicAuthenticatorFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthenticatorConfiguration {
    @Bean
    public BasicAuthAuthenticatorFactory basicAuthAuthenticatorFactory() {
        return new BasicAuthAuthenticatorFactory();
    }

    @Bean
    public BasicAuthOTPAuthenticatorFactory basicAuthOTPAuthenticatorFactory() {
        return new BasicAuthOTPAuthenticatorFactory();
    }

    @Bean
    public CliUsernamePasswordAuthenticatorFactory cliUsernamePasswordAuthenticatorFactory() {
        return new CliUsernamePasswordAuthenticatorFactory();
    }

    @Bean
    public ConditionalRoleAuthenticatorFactory conditionalAuthenticatorFactory() {
        return new ConditionalRoleAuthenticatorFactory();
    }

    @Bean
    public ConditionalUserConfiguredAuthenticatorFactory conditionalUserConfiguredAuthenticatorFactory() {
        return new ConditionalUserConfiguredAuthenticatorFactory();
    }

    @Bean
    public ConsoleUsernamePasswordAuthenticatorFactory consoleUsernamePasswordAuthenticatorFactory() {
        return new ConsoleUsernamePasswordAuthenticatorFactory();
    }

    @Bean
    public CookieAuthenticatorFactory cookieAuthenticatorFactory() {
        return new CookieAuthenticatorFactory();
    }

    @Bean
    public DockerAuthenticatorFactory dockerAuthenticatorFactory() {
        return new DockerAuthenticatorFactory();
    }

    @Bean
    public IdpUsernamePasswordFormFactory idpUsernamePasswordFormFactory() {
        return new IdpUsernamePasswordFormFactory();
    }

    @Bean
    public UsernamePasswordFormFactory usernamePasswordFormFactory() {
        return new UsernamePasswordFormFactory();
    }

    @Bean
    public HttpBasicAuthenticatorFactory httpBasicAuthenticatorFactory() {
        return new HttpBasicAuthenticatorFactory();
    }

    @Bean
    public NoCookieFlowRedirectAuthenticatorFactory noCookieFlowRedirectAuthenticatorFactory() {
        return new NoCookieFlowRedirectAuthenticatorFactory();
    }

    @Bean
    public IdpAutoLinkAuthenticatorFactory idpAutoLinkAuthenticatorFactory() {
        return new IdpAutoLinkAuthenticatorFactory();
    }

    @Bean
    public IdpConfirmLinkAuthenticatorFactory idpConfirmLinkAuthenticatorFactory() {
        return new IdpConfirmLinkAuthenticatorFactory();
    }

    @Bean
    public IdpEmailVerificationAuthenticatorFactory idpEmailVerificationAuthenticatorFactory() {
        return new IdpEmailVerificationAuthenticatorFactory();
    }

    @Bean
    public IdpCreateUserIfUniqueAuthenticatorFactory idpCreateUserIfUniqueAuthenticatorFactory() {
        return new IdpCreateUserIfUniqueAuthenticatorFactory();
    }

    @Bean
    public OTPFormAuthenticatorFactory otpFormAuthenticatorFactory() {
        return new OTPFormAuthenticatorFactory();
    }

    @Bean
    public ScriptBasedAuthenticatorFactory deployedScriptAuthenticatorFactory() {
        return new ScriptBasedAuthenticatorFactory();
    }

    @Bean
    public ResetOTP resetOTP() {
        return new ResetOTP();
    }

    @Bean
    public ResetCredentialEmail resetCredentialEmail() {
        return new ResetCredentialEmail();
    }

    @Bean
    public WebAuthnAuthenticatorFactory webAuthnAuthenticatorFactory() {
        return new WebAuthnAuthenticatorFactory();
    }

    @Bean
    public ValidateUsername validateUsername() {
        return new ValidateUsername();
    }

    @Bean
    public ValidateOTP validateOTP() {
        return new ValidateOTP();
    }

    @Bean
    public X509ClientCertificateAuthenticatorFactory x509ClientCertificateAuthenticatorFactory() {
        return new X509ClientCertificateAuthenticatorFactory();
    }

    @Bean
    public PasswordFormFactory passwordFormFactory() {
        return new PasswordFormFactory();
    }

    @Bean
    public WebAuthnPasswordlessAuthenticatorFactory webAuthnPasswordlessAuthenticatorFactory() {
        return new WebAuthnPasswordlessAuthenticatorFactory();
    }

    @Bean
    public ValidateX509CertificateUsernameFactory validateX509CertificateUsernameFactory() {
        return new ValidateX509CertificateUsernameFactory();
    }
}
