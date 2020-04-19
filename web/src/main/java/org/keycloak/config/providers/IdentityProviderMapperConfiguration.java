package org.keycloak.config.providers;

import org.keycloak.broker.oidc.mappers.ClaimToRoleMapper;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;
import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;
import org.keycloak.broker.provider.HardcodedAttributeMapper;
import org.keycloak.broker.provider.HardcodedRoleMapper;
import org.keycloak.broker.provider.HardcodedUserSessionAttributeMapper;
import org.keycloak.broker.saml.mappers.UserAttributeStatementMapper;
import org.keycloak.social.facebook.FacebookUserAttributeMapper;
import org.keycloak.social.github.GitHubUserAttributeMapper;
import org.keycloak.social.linkedin.LinkedInUserAttributeMapper;
import org.keycloak.social.microsoft.MicrosoftUserAttributeMapper;
import org.keycloak.social.paypal.PayPalUserAttributeMapper;
import org.keycloak.social.stackoverflow.StackoverflowUserAttributeMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IdentityProviderMapperConfiguration {
    @Bean
    public PayPalUserAttributeMapper payPalUserAttributeMapper() {
        return new PayPalUserAttributeMapper();
    }

    @Bean
    public GitHubUserAttributeMapper gitHubUserAttributeMapper() {
        return new GitHubUserAttributeMapper();
    }

    @Bean
    public MicrosoftUserAttributeMapper microsoftUserAttributeMapper() {
        return new MicrosoftUserAttributeMapper();
    }

    @Bean
    public ClaimToRoleMapper claimToRoleMapper() {
        return new ClaimToRoleMapper();
    }

    @Bean
    public HardcodedAttributeMapper hardcodedAttributeMapper() {
        return new HardcodedAttributeMapper();
    }

    @Bean
    public LinkedInUserAttributeMapper linkedInUserAttributeMapper() {
        return new LinkedInUserAttributeMapper();
    }

    @Bean
    public HardcodedUserSessionAttributeMapper hardcodedUserSessionAttributeMapper() {
        return new HardcodedUserSessionAttributeMapper();
    }

    @Bean
    public FacebookUserAttributeMapper facebookUserAttributeMapper() {
        return new FacebookUserAttributeMapper();
    }

    @Bean
    public HardcodedRoleMapper hardcodedRoleMapper() {
        return new HardcodedRoleMapper();
    }

    @Bean
    public UsernameTemplateMapper usernameTemplateMapper() {
        return new UsernameTemplateMapper();
    }

    @Bean
    public UserAttributeMapper userAttributeMapper() {
        return new UserAttributeMapper();
    }

    @Bean
    public UserAttributeStatementMapper userAttributeStatementMapper() {
        return new UserAttributeStatementMapper();
    }

    @Bean
    public org.keycloak.broker.saml.mappers.UsernameTemplateMapper samlUsernameTemplateMapper() {
        return new org.keycloak.broker.saml.mappers.UsernameTemplateMapper();
    }

    @Bean
    public StackoverflowUserAttributeMapper stackoverflowUserAttributeMapper() {
        return new StackoverflowUserAttributeMapper();
    }
}
