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
package org.keycloak.authentication.actiontoken.verifyemail;

import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandler;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.Objects;

/**
 * Action token handler for verification of e-mail address.
 *
 * @author hmlnarik
 */
@Component("VerifyEmailActionTokenHandler")
@ProviderFactory(id = "verify-email", providerClasses = ActionTokenHandler.class)
public class VerifyEmailActionTokenHandler extends AbstractActionTokenHandler<VerifyEmailActionToken> {
    public VerifyEmailActionTokenHandler() {
        super(
                VerifyEmailActionToken.class,
                Messages.STALE_VERIFY_EMAIL_LINK,
                EventType.VERIFY_EMAIL,
                Errors.INVALID_TOKEN
        );
    }

    @Override
    public String getId() {
        return VerifyEmailActionToken.TOKEN_TYPE;
    }

    @Override
    public Predicate<? super VerifyEmailActionToken>[] getVerifiers(ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        return TokenUtils.predicates(
                TokenUtils.checkThat(
                        t -> Objects.equals(t.getEmail(), tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
                        Errors.INVALID_EMAIL, getDefaultErrorMessage()
                )
        );
    }

    @Override
    public Response handleToken(VerifyEmailActionToken token, ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        EventBuilder event = tokenContext.getEvent();

        event.event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();
        final KeycloakSession session = tokenContext.getSession();

        if (tokenContext.isAuthenticationSessionFresh()) {
            // Update the authentication session in the token
            token.setCompoundOriginalAuthenticationSessionId(token.getCompoundAuthenticationSessionId());

            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId());
            String confirmUri = builder.build(realm.getName()).toString();

            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setSuccess(Messages.CONFIRM_EMAIL_ADDRESS_VERIFICATION, user.getEmail())
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .createInfoPage();
        }

        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);
        user.removeRequiredAction(RequiredAction.VERIFY_EMAIL);
        authSession.removeRequiredAction(RequiredAction.VERIFY_EMAIL);

        event.success();

        if (token.getCompoundOriginalAuthenticationSessionId() != null) {
            AuthenticationSessionManager asm = new AuthenticationSessionManager(tokenContext.getSession());
            asm.removeAuthenticationSession(tokenContext.getRealm(), authSession, true);

            return tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setSuccess(Messages.EMAIL_VERIFIED)
                    .createInfoPage();
        }

        tokenContext.setEvent(event.clone().removeDetail(Details.EMAIL).event(EventType.LOGIN));

        String nextAction = AuthenticationManager.nextRequiredAction(session, authSession, tokenContext.getClientConnection(), tokenContext.getRequest(), uriInfo, event);
        return AuthenticationManager.redirectToRequiredActions(session, realm, authSession, uriInfo, nextAction);
    }

}
