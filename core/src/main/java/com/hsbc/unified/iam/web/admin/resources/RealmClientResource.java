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
package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.facade.model.credential.UserCredentialModel;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.BadRequestException;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.admin.AuthorizationService;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.representations.adapters.action.GlobalRequestResult;
import org.keycloak.representations.idm.*;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.ResourceAdminManager;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.services.validation.ClientValidator;
import org.keycloak.services.validation.PairwiseClientValidator;
import org.keycloak.services.validation.ValidationMessages;
import org.keycloak.utils.ReservedCharValidator;
import org.keycloak.validation.ClientValidationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

import static java.lang.Boolean.TRUE;


/**
 * Base resource class for managing one particular client of a realm.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Clients
 */
public class RealmClientResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientResource.class);
    protected RealmModel realm;
    protected ClientModel client;
    @Context
    protected KeycloakApplication keycloak;
    @Context
    protected ClientConnection clientConnection;

    public RealmClientResource(RealmModel realm, ClientModel clientModel) {
        this.realm = realm;
        this.client = clientModel;
    }

    public static ManagementPermissionReference toMgmtRef(ClientModel client, AdminPermissionManagement permissions) {
        ManagementPermissionReference ref = new ManagementPermissionReference();
        ref.setEnabled(true);
        ref.setResource(permissions.clients().resource(client).getId());
        ref.setScopePermissions(permissions.clients().getPermissions(client));
        return ref;
    }

    protected KeycloakApplication getKeycloakApplication() {
        return keycloak;
    }

    @Path("protocol-mappers")
    public RealmProtocolMappersResource getProtocolMappers() {
        RealmProtocolMappersResource mappers = new RealmProtocolMappersResource(realm, client);
        ResteasyProviderFactory.getInstance().injectProperties(mappers);
        return mappers;
    }

    @Autowired
    private ClientValidationUtil clientValidationUtil;
    @Autowired
    private PairwiseClientValidator pairwiseClientValidator;
    @Autowired
    private AdminRoot adminRoot;

    /**
     * Update the client
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response update(final ClientRepresentation rep) {
        ValidationMessages validationMessages = new ValidationMessages();
        if (!ClientValidator.validate(rep, validationMessages) || !pairwiseClientValidator.validate(rep, validationMessages)) {
            Properties messages = adminRoot.getMessages(realm, Locale.getDefault().getLanguage());
            throw new ErrorResponseException(
                    validationMessages.getStringMessages(),
                    validationMessages.getStringMessages(messages),
                    Response.Status.BAD_REQUEST
            );
        }

        try {
            updateClientFromRep(rep, client);

            clientValidationUtil.validate(client, false, c -> {
                throw new ErrorResponseException(Errors.INVALID_INPUT, c.getError(), Response.Status.BAD_REQUEST);
            });

            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Client already exists");
        }
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    /**
     * Get representation of the client
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public ClientRepresentation getClient() {
        ClientRepresentation representation = modelToRepresentation.toRepresentation(client);

        // representation.setAccess(auth.clients().getAccess(client));

        return representation;
    }

    /**
     * Get representation of certificate resource
     */
    @Path("certificates/{attr}")
    public RealmClientAttributeCertificateResource getCertficateResource(@PathParam("attr") String attributePrefix) {
        return new RealmClientAttributeCertificateResource(realm, client, attributePrefix);
    }

    @Autowired
    private Map<String, ClientInstallationProvider> clientInstallationProviders;

    @GET
    @NoCache
    @Path("installation/providers/{providerId}")
    public Response getInstallationProvider(@PathParam("providerId") String providerId) {
        ClientInstallationProvider provider = clientInstallationProviders.get(providerId);
        if (provider == null) throw new NotFoundException("Unknown Provider");
        return provider.generateInstallation(realm, client, keycloakContext.getUri().getBaseUri());
    }

    /**
     * Delete the client
     */
    @DELETE
    @NoCache
    public void deleteClient() {
        if (client == null) {
            throw new NotFoundException("Could not find client");
        }

        new ClientManager(new RealmFacadeImpl()).removeClient(realm, client);
    }

    /**
     * Generate a new secret for the client
     */
    @Path("client-secret")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public CredentialRepresentation regenerateSecret() {
        LOG.debug("regenerateSecret");
        UserCredentialModel cred = KeycloakModelUtils.generateSecret(client);
        return ModelToRepresentation.toRepresentation(cred);
    }

    @Autowired
    private ClientRegistrationTokenUtils clientRegistrationTokenUtils;

    /**
     * Generate a new registration access token for the client
     */
    @Path("registration-access-token")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public ClientRepresentation regenerateRegistrationAccessToken() {
        String token = clientRegistrationTokenUtils.updateRegistrationAccessToken(realm, client, RegistrationAuth.AUTHENTICATED);

        ClientRepresentation rep = modelToRepresentation.toRepresentation(client);
        rep.setRegistrationAccessToken(token);
        return rep;
    }

    /**
     * Get the client secret
     */
    @Path("client-secret")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public CredentialRepresentation getClientSecret() {
        LOG.debug("getClientSecret");
        UserCredentialModel model = UserCredentialModel.secret(client.getSecret());
        return ModelToRepresentation.toRepresentation(model);
    }

    /**
     * Base path for managing the scope mappings for the client
     */
    @Path("scope-mappings")
    public RealmScopeMappedResource getScopeMappedResource() {
        return new RealmScopeMappedResource(realm, client);
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Path("roles")
    public RealmRolesResource getRoleContainerResource() {
        return new RealmRolesResource(keycloakContext.getUri(), realm, client);
    }

    /**
     * Get default client scopes.  Only name and ids are returned.
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Path("default-client-scopes")
    public List<ClientScopeRepresentation> getDefaultClientScopes() {
        return getDefaultClientScopes(true);
    }

    private List<ClientScopeRepresentation> getDefaultClientScopes(boolean defaultScope) {
        List<ClientScopeRepresentation> defaults = new LinkedList<>();
        for (ClientScopeModel clientScope : client.getClientScopes(defaultScope, true).values()) {
            ClientScopeRepresentation rep = new ClientScopeRepresentation();
            rep.setId(clientScope.getId());
            rep.setName(clientScope.getName());
            defaults.add(rep);
        }
        return defaults;
    }

    @PUT
    @NoCache
    @Path("default-client-scopes/{clientScopeId}")
    public void addDefaultClientScope(@PathParam("clientScopeId") String clientScopeId) {
        addDefaultClientScope(clientScopeId, true);
    }

    private void addDefaultClientScope(String clientScopeId, boolean defaultScope) {
        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new javax.ws.rs.NotFoundException("Client scope not found");
        }
        client.addClientScope(clientScope, defaultScope);
    }

    @DELETE
    @NoCache
    @Path("default-client-scopes/{clientScopeId}")
    public void removeDefaultClientScope(@PathParam("clientScopeId") String clientScopeId) {
        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new javax.ws.rs.NotFoundException("Client scope not found");
        }
        client.removeClientScope(clientScope);
    }

    /**
     * Get optional client scopes.  Only name and ids are returned.
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Path("optional-client-scopes")
    public List<ClientScopeRepresentation> getOptionalClientScopes() {
        return getDefaultClientScopes(false);
    }

    @PUT
    @NoCache
    @Path("optional-client-scopes/{clientScopeId}")
    public void addOptionalClientScope(@PathParam("clientScopeId") String clientScopeId) {
        addDefaultClientScope(clientScopeId, false);
    }

    @DELETE
    @NoCache
    @Path("optional-client-scopes/{clientScopeId}")
    public void removeOptionalClientScope(@PathParam("clientScopeId") String clientScopeId) {
        removeDefaultClientScope(clientScopeId);
    }

    @Path("evaluate-scopes")
    public RealmClientScopeEvaluateResource clientScopeEvaluateResource() {
        return new RealmClientScopeEvaluateResource(keycloakContext.getUri(), realm, client, clientConnection);
    }

    /**
     * Get a user dedicated to the service account
     */
    @Path("service-account-user")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public UserRepresentation getServiceAccountUser() {
        UserModel user = userProvider.getServiceAccount(client);
        if (user == null) {
            if (client.isServiceAccountsEnabled()) {
                new ClientManager(new RealmFacadeImpl()).enableServiceAccount(client);
                user = userProvider.getServiceAccount(client);
            } else {
                throw new BadRequestException("Service account not enabled for the client '" + client.getClientId() + "'");
            }
        }

        return modelToRepresentation.toRepresentation(realm, user);
    }

    /**
     * Push the client's revocation policy to its admin URL
     * <p>
     * If the client has an admin URL, push revocation policy to it.
     */
    @Path("push-revocation")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public GlobalRequestResult pushRevocation() {
        return new ResourceAdminManager().pushClientRevocationPolicy(realm, client);
    }

    /**
     * Get application session count
     * <p>
     * Returns a number of user sessions associated with this client
     * <p>
     * {
     * "count": number
     * }
     */
    @Path("session-count")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Long> getApplicationSessionCount() {
        Map<String, Long> map = new HashMap<>();
        map.put("count", userSessionProvider.getActiveUserSessions(client.getRealm(), client));
        return map;
    }

    /**
     * Get user sessions for client
     * <p>
     * Returns a list of user sessions associated with this client
     *
     * @param firstResult Paging offset
     * @param maxResults  Maximum results size (defaults to 100)
     */
    @Path("user-sessions")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserSessionRepresentation> getUserSessions(@QueryParam("first") Integer firstResult,
                                                           @QueryParam("max") Integer maxResults) {
        firstResult = firstResult != null ? firstResult : -1;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;
        List<UserSessionRepresentation> sessions = new ArrayList<>();
        for (UserSessionModel userSession : userSessionProvider.getUserSessions(client.getRealm(), client, firstResult, maxResults)) {
            UserSessionRepresentation rep = ModelToRepresentation.toRepresentation(userSession);
            sessions.add(rep);
        }
        return sessions;
    }

    /**
     * Get application offline session count
     * <p>
     * Returns a number of offline user sessions associated with this client
     * <p>
     * {
     * "count": number
     * }
     */
    @Path("offline-session-count")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Long> getOfflineSessionCount() {
        Map<String, Long> map = new HashMap<>();
        map.put("count", userSessionProvider.getOfflineSessionsCount(client.getRealm(), client));
        return map;
    }

    @Autowired
    private UserSessionProvider userSessionProvider;

    /**
     * Get offline sessions for client
     * <p>
     * Returns a list of offline user sessions associated with this client
     *
     * @param firstResult Paging offset
     * @param maxResults  Maximum results size (defaults to 100)
     */
    @Path("offline-sessions")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserSessionRepresentation> getOfflineUserSessions(@QueryParam("first") Integer firstResult, @QueryParam("max") Integer maxResults) {
        firstResult = firstResult != null ? firstResult : -1;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;
        List<UserSessionRepresentation> sessions = new ArrayList<UserSessionRepresentation>();
        List<UserSessionModel> userSessions = userSessionProvider.getOfflineUserSessions(client.getRealm(), client, firstResult, maxResults);
        for (UserSessionModel userSession : userSessions) {
            UserSessionRepresentation rep = ModelToRepresentation.toRepresentation(userSession);

            // Update lastSessionRefresh with the timestamp from clientSession
            for (Map.Entry<String, AuthenticatedClientSessionModel> csEntry : userSession.getAuthenticatedClientSessions().entrySet()) {
                String clientUuid = csEntry.getKey();
                AuthenticatedClientSessionModel clientSession = csEntry.getValue();

                if (client.getId().equals(clientUuid)) {
                    rep.setLastAccess(Time.toMillis(clientSession.getTimestamp()));
                    break;
                }
            }

            sessions.add(rep);
        }
        return sessions;
    }

    /**
     * Register a cluster node with the client
     * <p>
     * Manually register cluster node to this client - usually it's not needed to call this directly as adapter should handle
     * by sending registration request to Keycloak
     */
    @Path("nodes")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void registerNode(Map<String, String> formParams) {
        String node = formParams.get("node");
        if (node == null) {
            throw new BadRequestException("Node not found in params");
        }

        ReservedCharValidator.validate(node);

        if (LOG.isDebugEnabled()) LOG.debug("Register node: " + node);
        client.registerNode(node, Time.currentTime());
    }

    /**
     * Unregister a cluster node from the client
     */
    @Path("nodes/{node}")
    @DELETE
    @NoCache
    public void unregisterNode(final @PathParam("node") String node) {
        if (LOG.isDebugEnabled()) LOG.debug("Unregister node: " + node);

        Integer time = client.getRegisteredNodes().get(node);
        if (time == null) {
            throw new NotFoundException("Client does not have node ");
        }
        client.unregisterNode(node);
    }

    /**
     * Test if registered cluster nodes are available
     * <p>
     * Tests availability by sending 'ping' request to all cluster nodes.
     */
    @Path("test-nodes-available")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public GlobalRequestResult testNodesAvailable() {
        LOG.debug("Test availability of cluster nodes");
        return new ResourceAdminManager().testNodesAvailability(realm, client);
    }

    @Path("/authz")
    public AuthorizationService authorization() {
        AuthorizationService resource = new AuthorizationService(this.client);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     */
    @Path("management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions() {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (!permissions.clients().isPermissionsEnabled(client)) {
            return new ManagementPermissionReference();
        }
        return toMgmtRef(client, permissions);
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     *
     * @return initialized manage permissions reference
     */
    @Path("management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(ManagementPermissionReference ref) {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.clients().setPermissionsEnabled(client, ref.isEnabled());
        if (ref.isEnabled()) {
            return toMgmtRef(client, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

    @Autowired
    private UserProvider userProvider;

    private void updateClientFromRep(ClientRepresentation rep, ClientModel client) throws ModelDuplicateException {
        UserModel serviceAccount = userProvider.getServiceAccount(client);
        if (TRUE.equals(rep.isServiceAccountsEnabled())) {
            if (serviceAccount == null) {
                new ClientManager(new RealmFacadeImpl()).enableServiceAccount(client);
            }
        } else {
            if (serviceAccount != null) {
                new UserManager().removeUser(realm, serviceAccount);
            }
        }

        if (rep.getClientId() != null && !rep.getClientId().equals(client.getClientId())) {
            new ClientManager(new RealmFacadeImpl()).clientIdChanged(client, rep.getClientId());
        }

        if ((rep.isBearerOnly() != null && rep.isBearerOnly()) || (rep.isPublicClient() != null && rep.isPublicClient())) {
            rep.setAuthorizationServicesEnabled(false);
        }

        RepresentationToModel.updateClient(rep, client);
        updateAuthorizationSettings(rep);
    }

    private void updateAuthorizationSettings(ClientRepresentation rep) {
        if (TRUE.equals(rep.getAuthorizationServicesEnabled())) {
            authorization().enable(false);
        } else {
            authorization().disable();
        }
    }
}
