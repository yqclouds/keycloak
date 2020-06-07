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
package org.keycloak.authentication.actiontoken.idpverifyemail;

import com.hsbc.unified.iam.core.constants.Constants;
import lombok.Getter;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandler;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.Collections;

/**
 * Action token handler for verification of e-mail address.
 *
 * @author hmlnarik
 */
@Component("IdpVerifyAccountLinkActionTokenHandler")
@ProviderFactory(id = "idp-verify-account-via-email", providerClasses = ActionTokenHandler.class)
public class IdpVerifyAccountLinkActionTokenHandler extends AbstractActionTokenHandler<IdpVerifyAccountLinkActionToken> {
    @Value("${keycloak.provider.action-token-handler.idp-verify-account-via-email.id}")
    @Getter
    private String id;

    public IdpVerifyAccountLinkActionTokenHandler(Class<IdpVerifyAccountLinkActionToken> tokenClass,
                                                  String defaultErrorMessage,
                                                  EventType defaultEventType,
                                                  String defaultEventError) {
        super(
                IdpVerifyAccountLinkActionToken.class,
                Messages.STALE_CODE,
                EventType.IDENTITY_PROVIDER_LINK_ACCOUNT,
                Errors.INVALID_TOKEN
        );
    }

    @Override
    public Predicate<? super IdpVerifyAccountLinkActionToken>[] getVerifiers(ActionTokenContext<IdpVerifyAccountLinkActionToken> tokenContext) {
        return TokenUtils.predicates();
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;
    @Autowired
    private AuthenticationSessionProvider authenticationSessionProvider;

    @Override
    public Response handleToken(IdpVerifyAccountLinkActionToken token, ActionTokenContext<IdpVerifyAccountLinkActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        EventBuilder event = tokenContext.getEvent();
        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();

        event.event(EventType.IDENTITY_PROVIDER_LINK_ACCOUNT)
                .detail(Details.EMAIL, user.getEmail())
                .detail(Details.IDENTITY_PROVIDER, token.getIdentityProviderAlias())
                .detail(Details.IDENTITY_PROVIDER_USERNAME, token.getIdentityProviderUsername())
                .success();

        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        if (tokenContext.isAuthenticationSessionFresh()) {
            token.setOriginalCompoundAuthenticationSessionId(token.getCompoundAuthenticationSessionId());

            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId());
            String confirmUri = builder.build(realm.getName()).toString();

            return this.loginFormsProvider.setAuthenticationSession(authSession)
                    .setSuccess(Messages.CONFIRM_ACCOUNT_LINKING, token.getIdentityProviderUsername(), token.getIdentityProviderAlias())
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .createInfoPage();
        }

        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);

        if (token.getOriginalCompoundAuthenticationSessionId() != null) {
            AuthenticationSessionManager asm = new AuthenticationSessionManager();
            asm.removeAuthenticationSession(realm, authSession, true);

            AuthenticationSessionCompoundId compoundId = AuthenticationSessionCompoundId.encoded(token.getOriginalCompoundAuthenticationSessionId());
            ClientModel originalClient = realm.getClientById(compoundId.getClientUUID());
            authSession = asm.getAuthenticationSessionByIdAndClient(realm, compoundId.getRootSessionId(), originalClient, compoundId.getTabId());

            if (authSession != null) {
                authSession.setAuthNote(IdpEmailVerificationAuthenticator.VERIFY_ACCOUNT_IDP_USERNAME, token.getIdentityProviderUsername());
            } else {

                authenticationSessionProvider.updateNonlocalSessionAuthNotes(
                        compoundId,
                        Collections.singletonMap(IdpEmailVerificationAuthenticator.VERIFY_ACCOUNT_IDP_USERNAME, token.getIdentityProviderUsername())
                );
            }

            return this.loginFormsProvider.setAuthenticationSession(authSession)
                    .setSuccess(Messages.IDENTITY_PROVIDER_LINK_SUCCESS, token.getIdentityProviderAlias(), token.getIdentityProviderUsername())
                    .setAttribute(Constants.SKIP_LINK, true)
                    .createInfoPage();
        }

        authSession.setAuthNote(IdpEmailVerificationAuthenticator.VERIFY_ACCOUNT_IDP_USERNAME, token.getIdentityProviderUsername());

        return tokenContext.brokerFlow(null, null, authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH));
    }
}
