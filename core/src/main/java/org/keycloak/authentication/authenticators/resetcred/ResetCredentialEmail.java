/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.resetcred;

import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionToken;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("ResetCredentialEmail")
@ProviderFactory(id = "reset-credential-email", providerClasses = Authenticator.class)
public class ResetCredentialEmail implements Authenticator, AuthenticatorFactory {

    public static final String PROVIDER_ID = "reset-credential-email";
    public static final AuthenticationExecutionRequirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionRequirement.REQUIRED
    };
    private static final Logger LOG = LoggerFactory.getLogger(ResetCredentialEmail.class);

    @Autowired
    private EmailTemplateProvider emailTemplateProvider;
    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    public Long getLastChangedTimestamp(RealmModel realm, UserModel user) {
        // TODO(hmlnarik): Make this more generic to support non-password credential types
        PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) credentialProviders.get(PasswordCredentialProviderFactory.PROVIDER_ID);
        CredentialModel password = passwordProvider.getPassword(realm, user);

        return password == null ? null : password.getCreatedDate();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        String username = authenticationSession.getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);

        // we don't want people guessing usernames, so if there was a problem obtaining the user, the user will be null.
        // just reset login for with a success message
        if (user == null) {
            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            return;
        }

        String actionTokenUserId = authenticationSession.getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        if (actionTokenUserId != null && Objects.equals(user.getId(), actionTokenUserId)) {
            LOG.debug("Forget-password triggered when reauthenticating user after authentication via action token. Skipping " + PROVIDER_ID + " screen and using user '{}' ", user.getUsername());
            context.success();
            return;
        }


        EventBuilder event = context.getEvent();
        // we don't want people guessing usernames, so if there is a problem, just continuously challenge
        if (user.getEmail() == null || user.getEmail().trim().length() == 0) {
            event.user(user)
                    .detail(Details.USERNAME, username)
                    .error(Errors.INVALID_EMAIL);

            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            return;
        }

        int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan(ResetCredentialsActionToken.TOKEN_TYPE);
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        // We send the secret in the email in a link as a query param.
        String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authenticationSession).getEncodedId();
        ResetCredentialsActionToken token = new ResetCredentialsActionToken(user.getId(), absoluteExpirationInSecs, authSessionEncodedId, authenticationSession.getClient().getClientId());
        String link = UriBuilder
                .fromUri(context.getActionTokenUrl(token.serialize(context.getRealm(), context.getUriInfo())))
                .build()
                .toString();
        long expirationInMinutes = TimeUnit.SECONDS.toMinutes(validityInSecs);
        try {
            emailTemplateProvider.setRealm(context.getRealm()).setUser(user).setAuthenticationSession(authenticationSession).sendPasswordReset(link, expirationInMinutes);

            event.clone().event(EventType.SEND_RESET_PASSWORD)
                    .user(user)
                    .detail(Details.USERNAME, username)
                    .detail(Details.EMAIL, user.getEmail()).detail(Details.CODE_ID, authenticationSession.getParentSession().getId()).success();
            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
        } catch (EmailException e) {
            event.clone().event(EventType.SEND_RESET_PASSWORD)
                    .detail(Details.USERNAME, username)
                    .user(user)
                    .error(Errors.EMAIL_SEND_FAILED);
//            ServicesLogger.LOGGER.failedToSendPwdResetEmail(e);
            Response challenge = context.form()
                    .setError(Messages.EMAIL_SENT_ERROR)
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.getUser().setEmailVerified(true);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Send Reset Email";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionRequirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Send email to user and wait for response.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create() {
        return this;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
