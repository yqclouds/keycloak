package org.keycloak.authentication.config;

import liquibase.pro.packaged.B;
import org.keycloak.authentication.actiontoken.ActionTokenHandler;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionTokenHandler;
import org.keycloak.authentication.actiontoken.idpverifyemail.IdpVerifyAccountLinkActionToken;
import org.keycloak.authentication.actiontoken.idpverifyemail.IdpVerifyAccountLinkActionTokenHandler;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionToken;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionTokenHandler;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionToken;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionTokenHandler;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.messages.Messages;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class ActionTokenHandlerConfiguration {
    @Bean
    public ActionTokenHandler<ExecuteActionsActionToken> executeActionsActionTokenHandler() {
        return new ExecuteActionsActionTokenHandler(
                ExecuteActionsActionToken.class,
                Messages.INVALID_CODE,
                EventType.EXECUTE_ACTIONS,
                Errors.NOT_ALLOWED
        );
    }

    @Bean
    public ActionTokenHandler<IdpVerifyAccountLinkActionToken> idpVerifyAccountLinkActionTokenHandler() {
        return new IdpVerifyAccountLinkActionTokenHandler(
                IdpVerifyAccountLinkActionToken.class,
                Messages.STALE_CODE,
                EventType.IDENTITY_PROVIDER_LINK_ACCOUNT,
                Errors.INVALID_TOKEN
        );
    }

    @Bean
    public ActionTokenHandler<ResetCredentialsActionToken> resetCredentialsActionTokenHandler() {
        return new ResetCredentialsActionTokenHandler(
                ResetCredentialsActionToken.class,
                Messages.RESET_CREDENTIAL_NOT_ALLOWED,
                EventType.RESET_PASSWORD,
                Errors.NOT_ALLOWED
        );
    }

    @Bean
    public ActionTokenHandler<VerifyEmailActionToken> verifyEmailActionTokenHandler() {
        return new VerifyEmailActionTokenHandler(
                VerifyEmailActionToken.class,
                Messages.STALE_VERIFY_EMAIL_LINK,
                EventType.VERIFY_EMAIL,
                Errors.INVALID_TOKEN
        );
    }

    @Bean
    public Map<String, ActionTokenHandler<? extends JsonWebToken>> actionTokenHandlers() {
        Map<String, ActionTokenHandler<? extends JsonWebToken>> results = new HashMap<>();
        results.put("execute-actions", executeActionsActionTokenHandler());
        results.put("idp-verify-account-via-email", idpVerifyAccountLinkActionTokenHandler());
        results.put("reset-credentials", resetCredentialsActionTokenHandler());
        results.put("verify-email", verifyEmailActionTokenHandler());
        return results;
    }
}
