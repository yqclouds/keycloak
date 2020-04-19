package org.keycloak.config.providers;

import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionTokenHandler;
import org.keycloak.authentication.actiontoken.idpverifyemail.IdpVerifyAccountLinkActionTokenHandler;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionTokenHandler;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionTokenHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ActionTokenHandlerConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "keycloak", name = "enabled", havingValue = "true")
    public VerifyEmailActionTokenHandler verifyEmailActionTokenHandler() {
        return new VerifyEmailActionTokenHandler();
    }

    @Bean
    @ConditionalOnProperty(prefix = "keycloak", name = "enabled", havingValue = "true")
    public ResetCredentialsActionTokenHandler resetCredentialsActionTokenHandler() {
        return new ResetCredentialsActionTokenHandler();
    }

    @Bean
    @ConditionalOnProperty(prefix = "keycloak", name = "enabled", havingValue = "true")
    public IdpVerifyAccountLinkActionTokenHandler idpVerifyAccountLinkActionTokenHandler() {
        return new IdpVerifyAccountLinkActionTokenHandler();
    }

    @Bean
    @ConditionalOnProperty(prefix = "keycloak", name = "enabled", havingValue = "true")
    public ExecuteActionsActionTokenHandler executeActionsActionTokenHandler() {
        return new ExecuteActionsActionTokenHandler();
    }
}
