/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authentication.actiontoken.execactions;

import com.hsbc.unified.iam.core.constants.Constants;
import lombok.Getter;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandler;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.Objects;

/**
 * @author hmlnarik
 */
@Component("ExecuteActionsActionTokenHandler")
@ProviderFactory(id = "execute-actions", providerClasses = ActionTokenHandler.class)
public class ExecuteActionsActionTokenHandler extends AbstractActionTokenHandler<ExecuteActionsActionToken> {
    @Value("${keycloak.provider.action-token-handler.execute-actions.id}")
    @Getter
    private String id;

    public ExecuteActionsActionTokenHandler() {
        super(
                ExecuteActionsActionToken.class,
                Messages.INVALID_CODE,
                EventType.EXECUTE_ACTIONS,
                Errors.NOT_ALLOWED
        );
    }

    @Override
    public Predicate<? super ExecuteActionsActionToken>[] getVerifiers(ActionTokenContext<ExecuteActionsActionToken> tokenContext) {
        return TokenUtils.predicates(
                TokenUtils.checkThat(
                        // either redirect URI is not specified or must be valid for the client
                        t -> t.getRedirectUri() == null
                                || RedirectUtils.verifyRedirectUri(tokenContext.getSession(), t.getRedirectUri(),
                                tokenContext.getAuthenticationSession().getClient()) != null,
                        Errors.INVALID_REDIRECT_URI,
                        Messages.INVALID_REDIRECT_URI
                )
        );
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;

    @Override
    public Response handleToken(ExecuteActionsActionToken token, ActionTokenContext<ExecuteActionsActionToken> tokenContext) {
        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();
        final KeycloakSession session = tokenContext.getSession();
        if (tokenContext.isAuthenticationSessionFresh()) {
            // Update the authentication session in the token
            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId());
            String confirmUri = builder.build(realm.getName()).toString();

            return this.loginFormsProvider
                    .setAuthenticationSession(authSession)
                    .setSuccess(Messages.CONFIRM_EXECUTION_OF_ACTIONS)
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .setAttribute(Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions())
                    .createInfoPage();
        }

        String redirectUri = RedirectUtils.verifyRedirectUri(tokenContext.getSession(), token.getRedirectUri(), authSession.getClient());

        if (redirectUri != null) {
            authSession.setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");

            authSession.setRedirectUri(redirectUri);
            authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
        }

        token.getRequiredActions().stream().forEach(authSession::addRequiredAction);

        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);

        String nextAction = AuthenticationManager.nextRequiredAction(tokenContext.getSession(), authSession, tokenContext.getClientConnection(), tokenContext.getRequest(), tokenContext.getUriInfo(), tokenContext.getEvent());
        return AuthenticationManager.redirectToRequiredActions(tokenContext.getSession(), tokenContext.getRealm(), authSession, tokenContext.getUriInfo(), nextAction);
    }

    @Override
    public boolean canUseTokenRepeatedly(ExecuteActionsActionToken token, ActionTokenContext<ExecuteActionsActionToken> tokenContext) {
        RealmModel realm = tokenContext.getRealm();
        KeycloakSessionFactory sessionFactory = tokenContext.getSession().getSessionFactory();

        return token.getRequiredActions().stream()
                .map(actionName -> realm.getRequiredActionProviderByAlias(actionName))    // get realm-specific model from action name and filter out irrelevant
                .filter(Objects::nonNull)
                .filter(RequiredActionProviderModel::isEnabled)

                .map(RequiredActionProviderModel::getProviderId)      // get provider ID from model

                .map(providerId -> (RequiredActionFactory) sessionFactory.getProviderFactory(RequiredActionProvider.class, providerId))
                .filter(Objects::nonNull)

                .noneMatch(RequiredActionFactory::isOneTimeAction);
    }
}