package org.keycloak.config.providers;

import org.keycloak.social.bitbucket.BitbucketIdentityProviderFactory;
import org.keycloak.social.facebook.FacebookIdentityProviderFactory;
import org.keycloak.social.github.GitHubIdentityProviderFactory;
import org.keycloak.social.google.GoogleIdentityProviderFactory;
import org.keycloak.social.linkedin.LinkedInIdentityProviderFactory;
import org.keycloak.social.openshift.OpenshiftV3IdentityProviderFactory;
import org.keycloak.social.paypal.PayPalIdentityProviderFactory;
import org.keycloak.social.stackoverflow.StackoverflowIdentityProviderFactory;
import org.keycloak.social.twitter.TwitterIdentityProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SocialProviderConfiguration {
    @Bean
    public FacebookIdentityProviderFactory facebookIdentityProviderFactory() {
        return new FacebookIdentityProviderFactory();
    }

    @Bean
    public LinkedInIdentityProviderFactory linkedInIdentityProviderFactory() {
        return new LinkedInIdentityProviderFactory();
    }

    @Bean
    public GoogleIdentityProviderFactory googleIdentityProviderFactory() {
        return new GoogleIdentityProviderFactory();
    }

    @Bean
    public OpenshiftV3IdentityProviderFactory openshiftV3IdentityProviderFactory() {
        return new OpenshiftV3IdentityProviderFactory();
    }

    @Bean
    public TwitterIdentityProviderFactory twitterIdentityProviderFactory() {
        return new TwitterIdentityProviderFactory();
    }

    @Bean
    public StackoverflowIdentityProviderFactory stackoverflowIdentityProviderFactory() {
        return new StackoverflowIdentityProviderFactory();
    }

    @Bean
    public PayPalIdentityProviderFactory payPalIdentityProviderFactory() {
        return new PayPalIdentityProviderFactory();
    }

    @Bean
    public GitHubIdentityProviderFactory gitHubIdentityProviderFactory() {
        return new GitHubIdentityProviderFactory();
    }

    @Bean
    public BitbucketIdentityProviderFactory bitbucketIdentityProviderFactory() {
        return new BitbucketIdentityProviderFactory();
    }
}
