/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.services.resources.account;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.util.Base64Url;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.account.AccountLinkUriRepresentation;
import org.keycloak.representations.account.LinkedAccountRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.validation.Validation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import static com.hsbc.unified.iam.core.constants.Constants.ACCOUNT_CONSOLE_CLIENT_ID;

/**
 * API for linking/unlinking social login accounts
 *
 * @author Stan Silvert
 */
public class LinkedAccountsResource {
    private static final Logger LOG = LoggerFactory.getLogger(LinkedAccountsResource.class);

    private final HttpRequest request;
    private final ClientModel client;
    private final EventBuilder event;
    private final UserModel user;
    private final RealmModel realm;
    private final Auth auth;

    @Autowired
    private KeycloakContext keycloakContext;

    public LinkedAccountsResource(
            HttpRequest request,
            ClientModel client,
            Auth auth,
            EventBuilder event,
            UserModel user) {
        this.request = request;
        this.client = client;
        this.auth = auth;
        this.event = event;
        this.user = user;
        realm = keycloakContext.getRealm();
    }

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response linkedAccounts() {
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);
        SortedSet<LinkedAccountRepresentation> linkedAccounts = getLinkedAccounts(this.realm, this.user);
        return Cors.add(request, Response.ok(linkedAccounts)).auth().allowedOrigins(auth.getToken()).build();
    }

    @Autowired
    private UserProvider userProvider;

    public SortedSet<LinkedAccountRepresentation> getLinkedAccounts(RealmModel realm, UserModel user) {
        List<IdentityProviderModel> identityProviders = realm.getIdentityProviders();
        SortedSet<LinkedAccountRepresentation> linkedAccounts = new TreeSet<>();

        if (identityProviders == null || identityProviders.isEmpty()) return linkedAccounts;

        Set<FederatedIdentityModel> identities = userProvider.getFederatedIdentities(user, realm);
        for (IdentityProviderModel provider : identityProviders) {
            if (!provider.isEnabled()) {
                continue;
            }
            String providerId = provider.getAlias();

            FederatedIdentityModel identity = getIdentity(identities, providerId);

            String displayName = KeycloakModelUtils.getIdentityProviderDisplayName(provider);
            String guiOrder = provider.getConfig() != null ? provider.getConfig().get("guiOrder") : null;

            LinkedAccountRepresentation rep = new LinkedAccountRepresentation();
            rep.setConnected(identity != null);
            rep.setSocial(false);
            rep.setProviderAlias(providerId);
            rep.setDisplayName(displayName);
            rep.setGuiOrder(guiOrder);
            rep.setProviderName(provider.getAlias());
            if (identity != null) {
                rep.setLinkedUsername(identity.getUserName());
            }
            linkedAccounts.add(rep);
        }

        return linkedAccounts;
    }

    private FederatedIdentityModel getIdentity(Set<FederatedIdentityModel> identities, String providerId) {
        for (FederatedIdentityModel link : identities) {
            if (providerId.equals(link.getIdentityProvider())) {
                return link;
            }
        }
        return null;
    }

    @GET
    @Path("/{providerId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Deprecated
    public Response buildLinkedAccountURI(@PathParam("providerId") String providerId,
                                          @QueryParam("redirectUri") String redirectUri) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        if (redirectUri == null) {
            ErrorResponse.error(Messages.INVALID_REDIRECT_URI, Response.Status.BAD_REQUEST);
        }

        String errorMessage = checkCommonPreconditions(providerId);
        if (errorMessage != null) {
            return ErrorResponse.error(errorMessage, Response.Status.BAD_REQUEST);
        }

        try {
            String nonce = UUID.randomUUID().toString();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String input = nonce + auth.getSession().getId() + ACCOUNT_CONSOLE_CLIENT_ID + providerId;
            byte[] check = md.digest(input.getBytes(StandardCharsets.UTF_8));
            String hash = Base64Url.encode(check);
            URI linkUri = Urls.identityProviderLinkRequest(keycloakContext.getUri().getBaseUri(), providerId, realm.getName());
            linkUri = UriBuilder.fromUri(linkUri)
                    .queryParam("nonce", nonce)
                    .queryParam("hash", hash)
                    // need to use "account-console" client because IdentityBrokerService authenticates user using cookies
                    // the regular "account" client is used only for REST calls therefore cookies authentication cannot be used
                    .queryParam("client_id", ACCOUNT_CONSOLE_CLIENT_ID)
                    .queryParam("redirect_uri", redirectUri)
                    .build();

            AccountLinkUriRepresentation rep = new AccountLinkUriRepresentation();
            rep.setAccountLinkUri(linkUri);
            rep.setHash(hash);
            rep.setNonce(nonce);

            return Cors.add(request, Response.ok(rep)).auth().allowedOrigins(auth.getToken()).build();
        } catch (Exception spe) {
            spe.printStackTrace();
            return ErrorResponse.error(Messages.FAILED_TO_PROCESS_RESPONSE, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @DELETE
    @Path("/{providerId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeLinkedAccount(@PathParam("providerId") String providerId) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        String errorMessage = checkCommonPreconditions(providerId);
        if (errorMessage != null) {
            return ErrorResponse.error(errorMessage, Response.Status.BAD_REQUEST);
        }

        FederatedIdentityModel link = userProvider.getFederatedIdentity(user, providerId, realm);
        if (link == null) {
            return ErrorResponse.error(Messages.FEDERATED_IDENTITY_NOT_ACTIVE, Response.Status.BAD_REQUEST);
        }

        // Removing last social provider is not possible if you don't have other possibility to authenticate
        if (!(userProvider.getFederatedIdentities(user, realm).size() > 1 || user.getFederationLink() != null || isPasswordSet())) {
            return ErrorResponse.error(Messages.FEDERATED_IDENTITY_REMOVING_LAST_PROVIDER, Response.Status.BAD_REQUEST);
        }

        userProvider.removeFederatedIdentity(realm, user, providerId);

        LOG.debug("Social provider {} removed successfully from user {}", providerId, user.getUsername());

        event.event(EventType.REMOVE_FEDERATED_IDENTITY).client(auth.getClient()).user(auth.getUser())
                .detail(Details.USERNAME, auth.getUser().getUsername())
                .detail(Details.IDENTITY_PROVIDER, link.getIdentityProvider())
                .detail(Details.IDENTITY_PROVIDER_USERNAME, link.getUserName())
                .success();

        return Cors.add(request, Response.ok()).auth().allowedOrigins(auth.getToken()).build();
    }

    private String checkCommonPreconditions(String providerId) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        if (Validation.isEmpty(providerId)) {
            return Messages.MISSING_IDENTITY_PROVIDER;
        }

        if (!isValidProvider(providerId)) {
            return Messages.IDENTITY_PROVIDER_NOT_FOUND;
        }

        if (!user.isEnabled()) {
            return Messages.ACCOUNT_DISABLED;
        }

        return null;
    }

    @Autowired
    private UserCredentialManager userCredentialManager;

    private boolean isPasswordSet() {
        return userCredentialManager.isConfiguredFor(realm, user, PasswordCredentialModel.TYPE);
    }

    private boolean isValidProvider(String providerId) {
        for (IdentityProviderModel model : realm.getIdentityProviders()) {
            if (model.getAlias().equals(providerId)) {
                return true;
            }
        }

        return false;
    }
}
