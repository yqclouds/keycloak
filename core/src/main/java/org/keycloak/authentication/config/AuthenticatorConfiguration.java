package org.keycloak.authentication.config;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.authentication.authenticators.challenge.*;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.authentication.authenticators.directgrant.ValidatePassword;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.authentication.authenticators.resetcred.ResetOTP;
import org.keycloak.authentication.authenticators.resetcred.ResetPassword;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsername;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
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
        results.put("identity-provider-redirector", identityProviderAuthenticatorFactory());
        results.put("idp-auto-link", idpAutoLinkAuthenticatorFactory());
        results.put("idp-confirm-link", idpConfirmLinkAuthenticatorFactory());
        results.put("idp-create-user-if-unique", idpCreateUserIfUniqueAuthenticatorFactory());
        results.put("idp-email-verification", idpEmailVerificationAuthenticatorFactory());
        results.put("idp-review-profile", idpReviewProfileAuthenticatorFactory());
        results.put("idp-username-password-form", idpUsernamePasswordFormFactory());
        results.put("client-jwt", jwtClientAuthenticator());
        results.put("client-secret-jwt", jwtClientSecretAuthenticator());
        results.put("no-cookie-redirect", noCookieFlowRedirectAuthenticatorFactory());
        results.put("auth-otp-form", otpFormAuthenticatorFactory());
        results.put("auth-password-form", passwordFormFactory());
        results.put("reset-credentials-choose-user", resetCredentialChooseUser());
        results.put("reset-credential-email", resetCredentialEmail());
        results.put("reset-otp", resetOTP());
        results.put("reset-password", resetPassword());
        results.put("auth-username-form", usernameFormFactory());
        results.put("auth-username-password-form", usernamePasswordFormFactory());
        results.put("direct-grant-validate-otp", validateOTP());
        results.put("direct-grant-validate-password", validatePassword());
        results.put("direct-grant-validate-username", validateUsername());
        results.put("direct-grant-auth-x509-username", validateX509CertificateUsernameFactory());
        results.put("webauthn-authenticator", webAuthnAuthenticatorFactory());
        results.put("webauthn-authenticator-passwordless", webAuthnPasswordlessAuthenticatorFactory());
        results.put("client-x509", x509ClientAuthenticator());
        results.put("auth-x509-client-username-form", x509ClientCertificateAuthenticatorFactory());
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
    public IdentityProviderAuthenticatorFactory identityProviderAuthenticatorFactory() {
        return new IdentityProviderAuthenticatorFactory();
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
    public IdpCreateUserIfUniqueAuthenticatorFactory idpCreateUserIfUniqueAuthenticatorFactory() {
        return new IdpCreateUserIfUniqueAuthenticatorFactory();
    }

    @Bean
    public IdpEmailVerificationAuthenticatorFactory idpEmailVerificationAuthenticatorFactory() {
        return new IdpEmailVerificationAuthenticatorFactory();
    }

    @Bean
    public IdpReviewProfileAuthenticatorFactory idpReviewProfileAuthenticatorFactory() {
        return new IdpReviewProfileAuthenticatorFactory();
    }

    @Bean
    public IdpUsernamePasswordFormFactory idpUsernamePasswordFormFactory() {
        return new IdpUsernamePasswordFormFactory();
    }

    @Bean
    public NoCookieFlowRedirectAuthenticatorFactory noCookieFlowRedirectAuthenticatorFactory() {
        return new NoCookieFlowRedirectAuthenticatorFactory();
    }

    @Bean
    public OTPFormAuthenticatorFactory otpFormAuthenticatorFactory() {
        return new OTPFormAuthenticatorFactory();
    }

    @Bean
    public PasswordFormFactory passwordFormFactory() {
        return new PasswordFormFactory();
    }

    @Bean
    public ResetCredentialChooseUser resetCredentialChooseUser() {
        return new ResetCredentialChooseUser();
    }

    @Bean
    public ResetCredentialEmail resetCredentialEmail() {
        return new ResetCredentialEmail();
    }

    @Bean
    public ResetOTP resetOTP() {
        return new ResetOTP();
    }

    @Bean
    public ResetPassword resetPassword() {
        return new ResetPassword();
    }

    @Bean
    public UsernameFormFactory usernameFormFactory() {
        return new UsernameFormFactory();
    }

    @Bean
    public UsernamePasswordFormFactory usernamePasswordFormFactory() {
        return new UsernamePasswordFormFactory();
    }

    @Bean
    public ValidateOTP validateOTP() {
        return new ValidateOTP();
    }

    @Bean
    public ValidatePassword validatePassword() {
        return new ValidatePassword();
    }

    @Bean
    public ValidateUsername validateUsername() {
        return new ValidateUsername();
    }

    @Bean
    public ValidateX509CertificateUsernameFactory validateX509CertificateUsernameFactory() {
        return new ValidateX509CertificateUsernameFactory();
    }

    @Bean
    public WebAuthnAuthenticatorFactory webAuthnAuthenticatorFactory() {
        return new WebAuthnAuthenticatorFactory();
    }

    @Bean
    public WebAuthnPasswordlessAuthenticatorFactory webAuthnPasswordlessAuthenticatorFactory() {
        return new WebAuthnPasswordlessAuthenticatorFactory();
    }

    @Bean
    public X509ClientCertificateAuthenticatorFactory x509ClientCertificateAuthenticatorFactory() {
        return new X509ClientCertificateAuthenticatorFactory();
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
        results.put("identity-provider-redirector", identityProviderAuthenticator());
        results.put("idp-auto-link", idpAutoLinkAuthenticator());
        results.put("idp-confirm-link", idpConfirmLinkAuthenticator());
        results.put("idp-create-user-if-unique", idpCreateUserIfUniqueAuthenticator());
        results.put("idp-email-verification", idpEmailVerificationAuthenticator());
        results.put("idp-review-profile", idpReviewProfileAuthenticator());
        results.put("idp-username-password-form", usernamePasswordForm());
        results.put("no-cookie-redirect", noCookieFlowRedirectAuthenticator());
        results.put("auth-otp-form", otpFormAuthenticator());
        results.put("auth-password-form", passwordForm());
        results.put("reset-credentials-choose-user", resetCredentialChooseUser());
        results.put("reset-credential-email", resetCredentialEmail());
        results.put("reset-otp", resetOTP());
        results.put("reset-password", resetPassword());
        results.put("auth-username-form", usernameForm());
        results.put("auth-username-password-form", usernamePasswordForm());
        results.put("direct-grant-validate-otp", validateOTP());
        results.put("direct-grant-validate-password", validatePassword());
        results.put("direct-grant-validate-username", validateUsername());
        results.put("direct-grant-auth-x509-username", validateX509CertificateUsername());
        results.put("webauthn-authenticator", webAuthnAuthenticator());
        results.put("webauthn-authenticator-passwordless", webAuthnPasswordlessAuthenticator());
        results.put("auth-x509-client-username-form", x509ClientCertificateAuthenticator());
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
    public IdentityProviderAuthenticator identityProviderAuthenticator() {
        return new IdentityProviderAuthenticator();
    }

    @Bean
    public IdpAutoLinkAuthenticator idpAutoLinkAuthenticator() {
        return new IdpAutoLinkAuthenticator();
    }

    @Bean
    public IdpConfirmLinkAuthenticator idpConfirmLinkAuthenticator() {
        return new IdpConfirmLinkAuthenticator();
    }

    @Bean
    public IdpCreateUserIfUniqueAuthenticator idpCreateUserIfUniqueAuthenticator() {
        return new IdpCreateUserIfUniqueAuthenticator();
    }

    @Bean
    public IdpEmailVerificationAuthenticator idpEmailVerificationAuthenticator() {
        return new IdpEmailVerificationAuthenticator();
    }

    @Bean
    public IdpReviewProfileAuthenticator idpReviewProfileAuthenticator() {
        return new IdpReviewProfileAuthenticator();
    }

    @Bean
    public UsernamePasswordForm usernamePasswordForm() {
        return new UsernamePasswordForm();
    }

    @Bean
    public NoCookieFlowRedirectAuthenticator noCookieFlowRedirectAuthenticator() {
        return new NoCookieFlowRedirectAuthenticator();
    }

    @Bean
    public OTPFormAuthenticator otpFormAuthenticator() {
        return new OTPFormAuthenticator();
    }

    @Bean
    public PasswordForm passwordForm() {
        return new PasswordForm();
    }

    @Bean
    public UsernameForm usernameForm() {
        return new UsernameForm();
    }

    @Bean
    public ValidateX509CertificateUsername validateX509CertificateUsername() {
        return new ValidateX509CertificateUsername();
    }

    @Bean
    public WebAuthnAuthenticator webAuthnAuthenticator() {
        return new WebAuthnAuthenticator();
    }

    @Bean
    public WebAuthnPasswordlessAuthenticator webAuthnPasswordlessAuthenticator() {
        return new WebAuthnPasswordlessAuthenticator();
    }

    @Bean
    public X509ClientCertificateAuthenticator x509ClientCertificateAuthenticator() {
        return new X509ClientCertificateAuthenticator();
    }

    @Bean
    public Map<String, ClientAuthenticator> clientAuthenticators() {
        Map<String, ClientAuthenticator> results = new HashMap<>();
        results.put("client-secret", clientIdAndSecretAuthenticator());
        results.put("client-jwt", jwtClientAuthenticator());
        results.put("client-secret-jwt", jwtClientSecretAuthenticator());
        results.put("client-x509", x509ClientAuthenticator());
        return results;
    }

    @Bean
    public ClientIdAndSecretAuthenticator clientIdAndSecretAuthenticator() {
        return new ClientIdAndSecretAuthenticator();
    }

    @Bean
    public JWTClientAuthenticator jwtClientAuthenticator() {
        return new JWTClientAuthenticator();
    }

    @Bean
    public JWTClientSecretAuthenticator jwtClientSecretAuthenticator() {
        return new JWTClientSecretAuthenticator();
    }

    @Bean
    public X509ClientAuthenticator x509ClientAuthenticator() {
        return new X509ClientAuthenticator();
    }
}
