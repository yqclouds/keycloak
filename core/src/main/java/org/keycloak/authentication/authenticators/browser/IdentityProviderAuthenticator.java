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

package org.keycloak.authentication.authenticators.browser;

import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class IdentityProviderAuthenticator implements Authenticator {

    protected static final String ACCEPTS_PROMPT_NONE = "acceptsPromptNoneForwardFromClient";
    private static final Logger LOG = LoggerFactory.getLogger(IdentityProviderAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUriInfo().getQueryParameters().containsKey(AdapterConstants.KC_IDP_HINT)) {
            String providerId = context.getUriInfo().getQueryParameters().getFirst(AdapterConstants.KC_IDP_HINT);
            if (providerId == null || providerId.equals("")) {
                LOG.trace("Skipping: kc_idp_hint query parameter is empty");
                context.attempted();
            } else {
                LOG.trace("Redirecting: {} set to {}", AdapterConstants.KC_IDP_HINT, providerId);
                redirect(context, providerId);
            }
        } else if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig().containsKey(IdentityProviderAuthenticatorFactory.DEFAULT_PROVIDER)) {
            String defaultProvider = context.getAuthenticatorConfig().getConfig().get(IdentityProviderAuthenticatorFactory.DEFAULT_PROVIDER);
            LOG.trace("Redirecting: default provider set to {}", defaultProvider);
            redirect(context, defaultProvider);
        } else {
            LOG.trace("No default provider set or {} query parameter provided", AdapterConstants.KC_IDP_HINT);
            context.attempted();
        }
    }

    private void redirect(AuthenticationFlowContext context, String providerId) {
        List<IdentityProviderModel> identityProviders = context.getRealm().getIdentityProviders();
        for (IdentityProviderModel identityProvider : identityProviders) {
            if (identityProvider.isEnabled() && providerId.equals(identityProvider.getAlias())) {
                String accessCode = new ClientSessionCode<>(context.getRealm(), context.getAuthenticationSession()).getOrGenerateCode();
                String clientId = context.getAuthenticationSession().getClient().getClientId();
                String tabId = context.getAuthenticationSession().getTabId();
                URI location = Urls.identityProviderAuthnRequest(context.getUriInfo().getBaseUri(), providerId, context.getRealm().getName(), accessCode, clientId, tabId);
                if (context.getAuthenticationSession().getClientNote(OAuth2Constants.DISPLAY) != null) {
                    location = UriBuilder.fromUri(location).queryParam(OAuth2Constants.DISPLAY, context.getAuthenticationSession().getClientNote(OAuth2Constants.DISPLAY)).build();
                }
                Response response = Response.seeOther(location)
                        .build();
                // will forward the request to the IDP with prompt=none if the IDP accepts forwards with prompt=none.
                if ("none".equals(context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.PROMPT_PARAM)) &&
                        Boolean.parseBoolean(identityProvider.getConfig().get(ACCEPTS_PROMPT_NONE))) {
                    context.getAuthenticationSession().setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
                }
                LOG.debug("Redirecting to {}", providerId);
                context.forceChallenge(response);
                return;
            }
        }

        LOG.warn("Provider not found or not enabled for realm {}", providerId);
        context.attempted();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
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
    public void close() {
    }

}
