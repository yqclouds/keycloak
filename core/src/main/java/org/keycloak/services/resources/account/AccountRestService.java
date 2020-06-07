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
package org.keycloak.services.resources.account;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.util.StringPropertyReplacer;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.representations.account.ClientRepresentation;
import org.keycloak.representations.account.ConsentRepresentation;
import org.keycloak.representations.account.ConsentScopeRepresentation;
import org.keycloak.representations.account.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.resources.account.resources.ResourcesService;
import org.keycloak.storage.ReadOnlyException;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AccountRestService {

    private final ClientModel client;
    private final EventBuilder event;
    private final RealmModel realm;
    private final UserModel user;
    private final Locale locale;
    @Context
    protected HttpHeaders headers;
    @Context
    protected ClientConnection clientConnection;
    @Context
    private HttpRequest request;
    @Autowired
    private EventStoreProvider eventStore;
    private Auth auth;

    @Autowired
    private KeycloakContext keycloakContext;

    public AccountRestService(Auth auth, ClientModel client, EventBuilder event) {
        this.auth = auth;
        this.realm = auth.getRealm();
        this.user = auth.getUser();
        this.client = client;
        this.event = event;
        this.locale = keycloakContext.resolveLocale(user);
    }

    private static void checkAccountApiEnabled() {
        if (!Profile.isFeatureEnabled(Profile.Feature.ACCOUNT_API)) {
            throw new NotFoundException();
        }
    }

    /**
     * CORS preflight
     *
     * @return
     */
    @Path("/")
    @OPTIONS
    @NoCache
    public Response preflight() {
        return Cors.add(request, Response.ok()).auth().preflight().build();
    }

    /**
     * Get account information.
     *
     * @return
     */
    @Path("/")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response account() {
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);

        UserModel user = auth.getUser();

        UserRepresentation rep = new UserRepresentation();
        rep.setUsername(user.getUsername());
        rep.setFirstName(user.getFirstName());
        rep.setLastName(user.getLastName());
        rep.setEmail(user.getEmail());
        rep.setEmailVerified(user.isEmailVerified());
        rep.setAttributes(user.getAttributes());

        return Cors.add(request, Response.ok(rep)).auth().allowedOrigins(auth.getToken()).build();
    }

    @Autowired
    private UserProvider userProvider;

    @Path("/")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response updateAccount(UserRepresentation userRep) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        event.event(EventType.UPDATE_PROFILE).client(auth.getClient()).user(user);

        try {
            RealmModel realm = keycloakContext.getRealm();

            boolean usernameChanged = userRep.getUsername() != null && !userRep.getUsername().equals(user.getUsername());
            if (realm.isEditUsernameAllowed()) {
                if (usernameChanged) {
                    UserModel existing = userProvider.getUserByUsername(userRep.getUsername(), realm);
                    if (existing != null) {
                        return ErrorResponse.exists(Messages.USERNAME_EXISTS);
                    }

                    user.setUsername(userRep.getUsername());
                }
            } else if (usernameChanged) {
                return ErrorResponse.error(Messages.READ_ONLY_USERNAME, Response.Status.BAD_REQUEST);
            }

            boolean emailChanged = userRep.getEmail() != null && !userRep.getEmail().equals(user.getEmail());
            if (emailChanged && !realm.isDuplicateEmailsAllowed()) {
                UserModel existing = userProvider.getUserByEmail(userRep.getEmail(), realm);
                if (existing != null) {
                    return ErrorResponse.exists(Messages.EMAIL_EXISTS);
                }
            }

            if (emailChanged && realm.isRegistrationEmailAsUsername() && !realm.isDuplicateEmailsAllowed()) {
                UserModel existing = userProvider.getUserByUsername(userRep.getEmail(), realm);
                if (existing != null) {
                    return ErrorResponse.exists(Messages.USERNAME_EXISTS);
                }
            }

            if (emailChanged) {
                String oldEmail = user.getEmail();
                user.setEmail(userRep.getEmail());
                user.setEmailVerified(false);
                event.clone().event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, userRep.getEmail()).success();

                if (realm.isRegistrationEmailAsUsername()) {
                    user.setUsername(userRep.getEmail());
                }
            }

            user.setFirstName(userRep.getFirstName());
            user.setLastName(userRep.getLastName());

            if (userRep.getAttributes() != null) {
                for (String k : user.getAttributes().keySet()) {
                    if (!userRep.getAttributes().containsKey(k)) {
                        user.removeAttribute(k);
                    }
                }

                for (Map.Entry<String, List<String>> e : userRep.getAttributes().entrySet()) {
                    user.setAttribute(e.getKey(), e.getValue());
                }
            }

            event.success();

            return Cors.add(request, Response.ok()).auth().allowedOrigins(auth.getToken()).build();
        } catch (ReadOnlyException e) {
            return ErrorResponse.error(Messages.READ_ONLY_USER, Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Get session information.
     *
     * @return
     */
    @Path("/sessions")
    public SessionResource sessions() {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);
        return new SessionResource(auth, request);
    }

    @Path("/credentials")
    public AccountCredentialResource credentials() {
        checkAccountApiEnabled();
        return new AccountCredentialResource(event, user, auth);
    }

    // TODO Federated identities

    @Path("/resources")
    public ResourcesService resources() {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);
        return new ResourcesService(user, auth, request);
    }

    /**
     * Returns the applications with the given id in the specified realm.
     *
     * @param clientId client id to search for
     * @return application with the provided id
     */
    @Path("/applications/{clientId}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getApplication(final @PathParam("clientId") String clientId) {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_APPLICATIONS);
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || client.isBearerOnly() || client.getBaseUrl() == null) {
            return Cors.add(request, Response.status(Response.Status.NOT_FOUND).entity("No client with clientId: " + clientId + " found.")).build();
        }

        List<String> inUseClients = new LinkedList<>();
        if (!userSessionProvider.getUserSessions(realm, client).isEmpty()) {
            inUseClients.add(clientId);
        }

        List<String> offlineClients = new LinkedList<>();
        if (userSessionProvider.getOfflineSessionsCount(realm, client) > 0) {
            offlineClients.add(clientId);
        }

        UserConsentModel consentModel = userProvider.getConsentByClient(realm, user.getId(), client.getId());
        Map<String, UserConsentModel> consentModels = Collections.singletonMap(client.getClientId(), consentModel);

        return Cors.add(request, Response.ok(modelToRepresentation(client, inUseClients, offlineClients, consentModels))).build();
    }

    private ClientRepresentation modelToRepresentation(ClientModel model, List<String> inUseClients, List<String> offlineClients, Map<String, UserConsentModel> consents) {
        ClientRepresentation representation = new ClientRepresentation();
        representation.setClientId(model.getClientId());
        representation.setClientName(StringPropertyReplacer.replaceProperties(model.getName(), getProperties()));
        representation.setDescription(model.getDescription());
        representation.setUserConsentRequired(model.isConsentRequired());
        representation.setInUse(inUseClients.contains(model.getClientId()));
        representation.setOfflineAccess(offlineClients.contains(model.getClientId()));
        representation.setBaseUrl(model.getBaseUrl());
        UserConsentModel consentModel = consents.get(model.getClientId());
        if (consentModel != null) {
            representation.setConsent(modelToRepresentation(consentModel));
        }
        return representation;
    }

    private ConsentRepresentation modelToRepresentation(UserConsentModel model) {
        List<ConsentScopeRepresentation> grantedScopes = model.getGrantedClientScopes().stream()
                .map(m -> new ConsentScopeRepresentation(m.getId(), m.getName(), StringPropertyReplacer.replaceProperties(m.getConsentScreenText(), getProperties())))
                .collect(Collectors.toList());
        return new ConsentRepresentation(grantedScopes, model.getCreatedDate(), model.getLastUpdatedDate());
    }

    private Properties getProperties() {
        return null;
    }

    /**
     * Returns the consent for the client with the given client id.
     *
     * @param clientId client id to return the consent for
     * @return consent of the client
     */
    @Path("/applications/{clientId}/consent")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConsent(final @PathParam("clientId") String clientId) {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_CONSENT, AccountRoles.MANAGE_CONSENT);

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            return Cors.add(request, Response.status(Response.Status.NOT_FOUND).entity("No client with clientId: " + clientId + " found.")).build();
        }

        UserConsentModel consent = userProvider.getConsentByClient(realm, user.getId(), client.getId());
        if (consent == null) {
            return Cors.add(request, Response.noContent()).build();
        }

        return Cors.add(request, Response.ok(modelToRepresentation(consent))).build();
    }

    /**
     * Deletes the consent for the client with the given client id.
     *
     * @param clientId client id to delete a consent for
     * @return returns 202 if deleted
     */
    @Path("/applications/{clientId}/consent")
    @DELETE
    public Response revokeConsent(final @PathParam("clientId") String clientId) {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.MANAGE_CONSENT);

        event.event(EventType.REVOKE_GRANT);
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.event(EventType.REVOKE_GRANT_ERROR);
            String msg = String.format("No client with clientId: %s found.", clientId);
            event.error(msg);
            return Cors.add(request, Response.status(Response.Status.NOT_FOUND).entity(msg)).build();
        }

        userProvider.revokeConsentForClient(realm, user.getId(), client.getId());
        event.success();

        return Cors.add(request, Response.accepted()).build();
    }

    /**
     * Creates or updates the consent of the given, requested consent for
     * the client with the given client id. Returns the appropriate REST response.
     *
     * @param clientId client id to set a consent for
     * @param consent  requested consent for the client
     * @return the created or updated consent
     */
    @Path("/applications/{clientId}/consent")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response grantConsent(final @PathParam("clientId") String clientId,
                                 final ConsentRepresentation consent) {
        return upsert(clientId, consent);
    }

    /**
     * Creates or updates the consent of the given, requested consent for
     * the client with the given client id. Returns the appropriate REST response.
     *
     * @param clientId client id to set a consent for
     * @param consent  requested consent for the client
     * @return the created or updated consent
     */
    @Path("/applications/{clientId}/consent")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConsent(final @PathParam("clientId") String clientId,
                                  final ConsentRepresentation consent) {
        return upsert(clientId, consent);
    }

    @Autowired
    private UserCredentialManager userCredentialManager;

    @Path("/totp/remove")
    @DELETE
    public Response removeTOTP() {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        userCredentialManager.disableCredentialType(realm, user, CredentialModel.OTP);
        event.event(EventType.REMOVE_TOTP).client(auth.getClient()).user(auth.getUser()).success();

        return Cors.add(request, Response.accepted()).build();
    }

    /**
     * Creates or updates the consent of the given, requested consent for
     * the client with the given client id. Returns the appropriate REST response.
     *
     * @param clientId client id to set a consent for
     * @param consent  requested consent for the client
     * @return response to return to the caller
     */
    private Response upsert(String clientId, ConsentRepresentation consent) {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.MANAGE_CONSENT);

        event.event(EventType.GRANT_CONSENT);
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.event(EventType.GRANT_CONSENT_ERROR);
            String msg = String.format("No client with clientId: %s found.", clientId);
            event.error(msg);
            return Cors.add(request, Response.status(Response.Status.NOT_FOUND).entity(msg)).build();
        }

        try {
            UserConsentModel grantedConsent = createConsent(client, consent);
            if (userProvider.getConsentByClient(realm, user.getId(), client.getId()) == null) {
                userProvider.addConsent(realm, user.getId(), grantedConsent);
            } else {
                userProvider.updateConsent(realm, user.getId(), grantedConsent);
            }
            event.success();
            grantedConsent = userProvider.getConsentByClient(realm, user.getId(), client.getId());
            return Cors.add(request, Response.ok(modelToRepresentation(grantedConsent))).build();
        } catch (IllegalArgumentException e) {
            return Cors.add(request, Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage())).build();
        }
    }

    /**
     * Create a new consent model object from the requested consent object
     * for the given client model.
     *
     * @param client    client to create a consent for
     * @param requested list of client scopes that the new consent should contain
     * @return newly created consent model
     * @throws IllegalArgumentException throws an exception if the scope id is not available
     */
    private UserConsentModel createConsent(ClientModel client, ConsentRepresentation requested) throws IllegalArgumentException {
        UserConsentModel consent = new UserConsentModel(client);
        Map<String, ClientScopeModel> availableGrants = realm.getClientScopes().stream().collect(Collectors.toMap(ClientScopeModel::getId, s -> s));

        if (client.isConsentRequired()) {
            availableGrants.put(client.getId(), client);
        }

        for (ConsentScopeRepresentation scopeRepresentation : requested.getGrantedScopes()) {
            ClientScopeModel scopeModel = availableGrants.get(scopeRepresentation.getId());
            if (scopeModel == null) {
                String msg = String.format("ScopeModel id %s does not exist for client %s.", scopeRepresentation, consent.getClient().getName());
                event.error(msg);
                throw new IllegalArgumentException(msg);
            } else {
                consent.addGrantedClientScope(scopeModel);
            }
        }
        return consent;
    }

    @Path("/linked-accounts")
    public LinkedAccountsResource linkedAccounts() {
        return new LinkedAccountsResource(request, client, auth, event, user);
    }

    @Autowired
    private UserSessionProvider userSessionProvider;

    // TODO Logs

    @Path("/applications")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response applications() {
        checkAccountApiEnabled();
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_APPLICATIONS);

        Set<ClientModel> clients = new HashSet<ClientModel>();
        List<String> inUseClients = new LinkedList<String>();
        List<UserSessionModel> sessions = userSessionProvider.getUserSessions(realm, user);
        for (UserSessionModel s : sessions) {
            for (AuthenticatedClientSessionModel a : s.getAuthenticatedClientSessions().values()) {
                ClientModel client = a.getClient();
                clients.add(client);
                inUseClients.add(client.getClientId());
            }
        }

        List<String> offlineClients = new LinkedList<String>();
        List<UserSessionModel> offlineSessions = userSessionProvider.getOfflineUserSessions(realm, user);
        for (UserSessionModel s : offlineSessions) {
            for (AuthenticatedClientSessionModel a : s.getAuthenticatedClientSessions().values()) {
                ClientModel client = a.getClient();
                clients.add(client);
                offlineClients.add(client.getClientId());
            }
        }

        Map<String, UserConsentModel> consentModels = new HashMap<String, UserConsentModel>();
        List<UserConsentModel> consents = userProvider.getConsents(realm, user.getId());
        for (UserConsentModel consent : consents) {
            ClientModel client = consent.getClient();
            clients.add(client);
            consentModels.put(client.getClientId(), consent);
        }

        List<ClientModel> alwaysDisplayClients = realm.getAlwaysDisplayInConsoleClients();
        for (ClientModel client : alwaysDisplayClients) {
            clients.add(client);
        }

        List<ClientRepresentation> apps = new LinkedList<ClientRepresentation>();
        for (ClientModel client : clients) {
            if (client.isBearerOnly() || client.getBaseUrl() == null) {
                continue;
            }
            apps.add(modelToRepresentation(client, inUseClients, offlineClients, consentModels));
        }

        return Cors.add(request, Response.ok(apps)).auth().allowedOrigins(auth.getToken()).build();
    }
}
