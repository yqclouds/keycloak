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
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.Profile;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.idm.*;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.account.AccountFormService;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.validation.Validation;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.utils.ProfileHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;
import java.net.URI;
import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_ID;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_USERNAME;

/**
 * Base resource for managing users
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Users
 */
public class RealmUserResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmUserResource.class);

    protected RealmModel realm;
    @Context
    protected ClientConnection clientConnection;
    @Context
    protected HttpHeaders headers;
    private UserModel user;

    @Autowired
    private UserCredentialManager userCredentialManager;

    @Autowired
    private Map<String, RequiredActionFactory> requiredActionFactories;

    public RealmUserResource(RealmModel realm, UserModel user) {
        this.realm = realm;
        this.user = user;
    }

    public void updateUserFromRep(UserModel user, UserRepresentation rep, Set<String> attrsToRemove, RealmModel realm, boolean removeMissingRequiredActions) {
        if (rep.getUsername() != null && realm.isEditUsernameAllowed() && !realm.isRegistrationEmailAsUsername()) {
            user.setUsername(rep.getUsername());
        }
        if (rep.getEmail() != null) {
            String email = rep.getEmail();
            user.setEmail(email);
            if (realm.isRegistrationEmailAsUsername()) {
                user.setUsername(email);
            }
        }
        if (rep.getEmail().equals("")) user.setEmail(null);
        if (rep.getFirstName() != null) user.setFirstName(rep.getFirstName());
        if (rep.getLastName() != null) user.setLastName(rep.getLastName());

        if (rep.isEnabled() != null) user.setEnabled(rep.isEnabled());
        if (rep.isEmailVerified() != null) user.setEmailVerified(rep.isEmailVerified());

        if (rep.getFederationLink() != null) user.setFederationLink(rep.getFederationLink());

        List<String> reqActions = rep.getRequiredActions();

        if (reqActions != null) {
            Set<String> allActions = new HashSet<>();
            for (RequiredActionFactory factory : requiredActionFactories.values()) {
                allActions.add(factory.getId());
            }
            for (String action : allActions) {
                if (reqActions.contains(action)) {
                    user.addRequiredAction(action);
                } else if (removeMissingRequiredActions) {
                    user.removeRequiredAction(action);
                }
            }
        }

        List<CredentialRepresentation> credentials = rep.getCredentials();
        if (credentials != null) {
            for (CredentialRepresentation credential : credentials) {
                if (CredentialRepresentation.PASSWORD.equals(credential.getType()) && credential.isTemporary() != null
                        && credential.isTemporary()) {
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                }
            }
        }

        if (rep.getAttributes() != null) {
            for (Map.Entry<String, List<String>> attr : rep.getAttributes().entrySet()) {
                user.setAttribute(attr.getKey(), attr.getValue());
            }

            for (String attr : attrsToRemove) {
                user.removeAttribute(attr);
            }
        }
    }

    @Autowired
    private UserSessionProvider userSessionProvider;

    /**
     * Update the user
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUser(final UserRepresentation rep) {
        try {
            Set<String> attrsToRemove;
            if (rep.getAttributes() != null) {
                attrsToRemove = new HashSet<>(user.getAttributes().keySet());
                attrsToRemove.removeAll(rep.getAttributes().keySet());
            } else {
                attrsToRemove = Collections.emptySet();
            }

            if (rep.isEnabled() != null && rep.isEnabled()) {
                UserLoginFailureModel failureModel = userSessionProvider.getUserLoginFailure(realm, user.getId());
                if (failureModel != null) {
                    failureModel.clearFailures();
                }
            }

            updateUserFromRep(user, rep, attrsToRemove, realm, true);
            representationToModel.createCredentials(rep, realm, user, true);
            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("User exists with same username or email");
        } catch (ReadOnlyException re) {
            return ErrorResponse.exists("User is read only!");
        } catch (ForbiddenException fe) {
            throw fe;
        } catch (Exception me) {
            LOG.warn("Could not update user!", me);
            return ErrorResponse.exists("Could not update user!");
        }
    }

    @Autowired
    private BruteForceProtector bruteForceProtector;
    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private ModelToRepresentation modelToRepresentation;

    /**
     * Get representation of the user
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public UserRepresentation getUser() {
        UserRepresentation rep = modelToRepresentation.toRepresentation(realm, user);

        if (realm.isIdentityFederationEnabled()) {
            List<FederatedIdentityRepresentation> reps = getFederatedIdentities(user);
            rep.setFederatedIdentities(reps);
        }

        if (bruteForceProtector.isTemporarilyDisabled(realm, user)) {
            rep.setEnabled(false);
        }
//        rep.setAccess(auth.users().getAccess(user));

        return rep;
    }

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private KeycloakContext keycloakContext;

    @Autowired
    private AdminAuth adminAuth;

    /**
     * Impersonate the user
     */
    @Path("impersonation")
    @POST
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> impersonate() {
        ProfileHelper.requireFeature(Profile.Feature.IMPERSONATION);

        RealmModel authenticatedRealm = adminAuth.getRealm();
        // if same realm logout before impersonation
        boolean sameRealm = false;
        if (authenticatedRealm.getId().equals(realm.getId())) {
            sameRealm = true;
            UserSessionModel userSession = userSessionProvider.getUserSession(authenticatedRealm, adminAuth.getToken().getSessionState());
            AuthenticationManager.expireIdentityCookie(realm, keycloakContext.getUri(), clientConnection);
            AuthenticationManager.expireRememberMeCookie(realm, keycloakContext.getUri(), clientConnection);
            authenticationManager.backchannelLogout(authenticatedRealm, userSession, keycloakContext.getUri(), clientConnection, headers, true);
        }
        EventBuilder event = new EventBuilder(realm, clientConnection);

        UserSessionModel userSession = userSessionProvider.createUserSession(realm, user, user.getUsername(), clientConnection.getRemoteAddr(), "impersonate", false, null, null);

        UserModel adminUser = null; // auth.adminAuth().getUser();
        String impersonatorId = adminUser.getId();
        String impersonator = adminUser.getUsername();
        userSession.setNote(IMPERSONATOR_ID.toString(), impersonatorId);
        userSession.setNote(IMPERSONATOR_USERNAME.toString(), impersonator);

        authenticationManager.createLoginCookie(realm, userSession.getUser(), userSession, keycloakContext.getUri(), clientConnection);
        URI redirect = AccountFormService.accountServiceApplicationPage(keycloakContext.getUri()).build(realm.getName());
        Map<String, Object> result = new HashMap<>();
        result.put("sameRealm", sameRealm);
        result.put("redirect", redirect.toString());
        event.event(EventType.IMPERSONATE)
                .session(userSession)
                .user(user)
                .detail(Details.IMPERSONATOR_REALM, authenticatedRealm.getName())
                .detail(Details.IMPERSONATOR, impersonator).success();

        return result;
    }


    /**
     * Get sessions associated with the user
     */
    @Path("sessions")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserSessionRepresentation> getSessions() {
        List<UserSessionModel> sessions = userSessionProvider.getUserSessions(realm, user);
        List<UserSessionRepresentation> reps = new ArrayList<>();
        for (UserSessionModel session : sessions) {
            UserSessionRepresentation rep = ModelToRepresentation.toRepresentation(session);
            reps.add(rep);
        }
        return reps;
    }

    /**
     * Get offline sessions associated with the user and client
     */
    @Path("offline-sessions/{clientId}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserSessionRepresentation> getOfflineSessions(final @PathParam("clientId") String clientId) {
        ClientModel client = realm.getClientById(clientId);
        if (client == null) {
            throw new NotFoundException("Client not found");
        }
        List<UserSessionModel> sessions = new UserSessionManager().findOfflineSessions(realm, user);
        List<UserSessionRepresentation> reps = new ArrayList<>();
        for (UserSessionModel session : sessions) {
            UserSessionRepresentation rep = ModelToRepresentation.toRepresentation(session);

            // Update lastSessionRefresh with the timestamp from clientSession
            AuthenticatedClientSessionModel clientSession = session.getAuthenticatedClientSessionByClient(clientId);

            // Skip if userSession is not for this client
            if (clientSession == null) {
                continue;
            }

            rep.setLastAccess(clientSession.getTimestamp());

            reps.add(rep);
        }
        return reps;
    }

    @Autowired
    private UserProvider userProvider;

    /**
     * Get social logins associated with the user
     */
    @Path("federated-identity")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<FederatedIdentityRepresentation> getFederatedIdentity() {
        return getFederatedIdentities(user);
    }

    private List<FederatedIdentityRepresentation> getFederatedIdentities(UserModel user) {
        Set<FederatedIdentityModel> identities = userProvider.getFederatedIdentities(user, realm);
        List<FederatedIdentityRepresentation> result = new ArrayList<>();

        for (FederatedIdentityModel identity : identities) {
            for (IdentityProviderModel identityProviderModel : realm.getIdentityProviders()) {
                if (identityProviderModel.getAlias().equals(identity.getIdentityProvider())) {
                    FederatedIdentityRepresentation rep = ModelToRepresentation.toRepresentation(identity);
                    result.add(rep);
                }
            }
        }
        return result;
    }

    /**
     * Add a social login provider to the user
     *
     * @param provider Social login provider id
     */
    @Path("federated-identity/{provider}")
    @POST
    @NoCache
    public Response addFederatedIdentity(final @PathParam("provider") String provider, FederatedIdentityRepresentation rep) {
        if (userProvider.getFederatedIdentity(user, provider, realm) != null) {
            return ErrorResponse.exists("User is already linked with provider");
        }

        FederatedIdentityModel socialLink = new FederatedIdentityModel(provider, rep.getUserId(), rep.getUserName());
        userProvider.addFederatedIdentity(realm, user, socialLink);
        return Response.noContent().build();
    }

    /**
     * Remove a social login provider from user
     *
     * @param provider Social login provider id
     */
    @Path("federated-identity/{provider}")
    @DELETE
    @NoCache
    public void removeFederatedIdentity(final @PathParam("provider") String provider) {
        if (!userProvider.removeFederatedIdentity(realm, user, provider)) {
            throw new NotFoundException("Link not found");
        }
    }

    /**
     * Get consents granted by the user
     */
    @Path("consents")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> getConsents() {
        List<Map<String, Object>> result = new LinkedList<>();

        Set<ClientModel> offlineClients = new UserSessionManager().findClientsWithOfflineToken(realm, user);

        for (ClientModel client : realm.getClients()) {
            UserConsentModel consent = userProvider.getConsentByClient(realm, user.getId(), client.getId());
            boolean hasOfflineToken = offlineClients.contains(client);

            if (consent == null && !hasOfflineToken) {
                continue;
            }

            UserConsentRepresentation rep = (consent == null) ? null : ModelToRepresentation.toRepresentation(consent);

            Map<String, Object> currentRep = new HashMap<>();
            currentRep.put("clientId", client.getClientId());
            currentRep.put("grantedClientScopes", (rep == null ? Collections.emptyList() : rep.getGrantedClientScopes()));
            currentRep.put("createdDate", (rep == null ? null : rep.getCreatedDate()));
            currentRep.put("lastUpdatedDate", (rep == null ? null : rep.getLastUpdatedDate()));

            List<Map<String, String>> additionalGrants = new LinkedList<>();
            if (hasOfflineToken) {
                Map<String, String> offlineTokens = new HashMap<>();
                offlineTokens.put("client", client.getId());
                // TODO: translate
                offlineTokens.put("key", "Offline Token");
                additionalGrants.add(offlineTokens);
            }
            currentRep.put("additionalGrants", additionalGrants);

            result.add(currentRep);
        }

        return result;
    }


    /**
     * Revoke consent and offline tokens for particular client from user
     *
     * @param clientId Client id
     */
    @Path("consents/{client}")
    @DELETE
    @NoCache
    public void revokeConsent(final @PathParam("client") String clientId) {
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            throw new NotFoundException("Client not found");
        }
        boolean revokedConsent = userProvider.revokeConsentForClient(realm, user.getId(), client.getId());
        boolean revokedOfflineToken = new UserSessionManager().revokeOfflineToken(user, client);

        if (revokedConsent) {
            // Logout clientSessions for this user and client
            authenticationManager.backchannelLogoutUserFromClient(realm, user, client, keycloakContext.getUri(), headers);
        }

        if (!revokedConsent && !revokedOfflineToken) {
            throw new NotFoundException("Consent nor offline token not found");
        }
    }

    /**
     * Remove all user sessions associated with the user
     * <p>
     * Also send notification to all clients that have an admin URL to invalidate the sessions for the particular user.
     */
    @Path("logout")
    @POST
    public void logout() {
        userProvider.setNotBeforeForUser(realm, user, Time.currentTime());

        List<UserSessionModel> userSessions = userSessionProvider.getUserSessions(realm, user);
        for (UserSessionModel userSession : userSessions) {
            authenticationManager.backchannelLogout(realm, userSession, keycloakContext.getUri(), clientConnection, headers, true);
        }
    }

    /**
     * Delete the user
     */
    @DELETE
    @NoCache
    public Response deleteUser() {
        boolean removed = new UserManager().removeUser(realm, user);
        if (removed) {
            return Response.noContent().build();
        } else {
            return ErrorResponse.error("User couldn't be deleted", Status.BAD_REQUEST);
        }
    }

    @Path("role-mappings")
    public RealmRoleMapperResource getRoleMappings() {
        RealmRoleMapperResource resource = new RealmRoleMapperResource(realm, user);
        ResteasyProviderFactory.getInstance().injectProperties(resource);
        return resource;

    }

    /**
     * Disable all credentials for a user of a specific type
     */
    @Path("disable-credential-types")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void disableCredentialType(List<String> credentialTypes) {
        if (credentialTypes == null) return;
        for (String type : credentialTypes) {
            userCredentialManager.disableCredentialType(realm, user, type);
        }
    }

    @Autowired
    private AdminRoot adminRoot;

    /**
     * Set up a new password for the user.
     *
     * @param cred The representation must contain a rawPassword with the plain-text password
     */
    @Path("reset-password")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void resetPassword(CredentialRepresentation cred) {
        if (cred == null || cred.getValue() == null) {
            throw new BadRequestException("No password provided");
        }
        if (Validation.isBlank(cred.getValue())) {
            throw new BadRequestException("Empty password not allowed");
        }

        try {
            userCredentialManager.updateCredential(realm, user, UserCredentialModel.password(cred.getValue(), false));
        } catch (IllegalStateException ise) {
            throw new BadRequestException("Resetting to N old passwords is not allowed.");
        } catch (ReadOnlyException mre) {
            throw new BadRequestException("Can't reset password as account is read only");
        } catch (ModelException e) {
            Properties messages = adminRoot.getMessages(realm, adminAuth.getToken().getLocale());
            throw new ErrorResponseException(e.getMessage(), MessageFormat.format(messages.getProperty(e.getMessage(), e.getMessage()), e.getParameters()),
                    Status.BAD_REQUEST);
        }
        if (cred.isTemporary() != null && cred.isTemporary())
            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    }


    @GET
    @Path("credentials")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<CredentialRepresentation> credentials() {
        List<CredentialModel> models = userCredentialManager.getStoredCredentials(realm, user);
        models.forEach(c -> c.setSecretData(null));
        return models.stream().map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
    }

    /**
     * Return credential types, which are provided by the user storage where user is stored. Returned values can contain for example "password", "otp" etc.
     * This will always return empty list for "local" users, which are not backed by any user storage
     */
    @GET
    @Path("configured-user-storage-credential-types")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<String> getConfiguredUserStorageCredentialTypes() {
        // This has "requireManage" due the compatibility with "credentials()" endpoint. Strictly said, it is reading endpoint, not writing,
        // so may be revisited if to rather use "requireView" here in the future.
        return userCredentialManager.getConfiguredUserStorageCredentialTypes(realm, user);
    }


    /**
     * Remove a credential for a user
     */
    @Path("credentials/{credentialId}")
    @DELETE
    @NoCache
    public void removeCredential(final @PathParam("credentialId") String credentialId) {
        userCredentialManager.removeStoredCredential(realm, user, credentialId);
    }

    /**
     * Update a credential label for a user
     */
    @PUT
    @Consumes(javax.ws.rs.core.MediaType.TEXT_PLAIN)
    @Path("credentials/{credentialId}/userLabel")
    public void setCredentialUserLabel(final @PathParam("credentialId") String credentialId, String userLabel) {
        CredentialModel credential = userCredentialManager.getStoredCredentialById(realm, user, credentialId);
        if (credential == null) {
            throw new NotFoundException("User not found");
        }
        userCredentialManager.updateCredentialLabel(realm, user, credentialId, userLabel);
    }

    /**
     * Move a credential to a first position in the credentials list of the user
     *
     * @param credentialId The credential to move
     */
    @Path("credentials/{credentialId}/moveToFirst")
    @POST
    public void moveCredentialToFirst(final @PathParam("credentialId") String credentialId) {
        moveCredentialAfter(credentialId, null);
    }

    /**
     * Move a credential to a position behind another credential
     *
     * @param credentialId            The credential to move
     * @param newPreviousCredentialId The credential that will be the previous element in the list. If set to null, the moved credential will be the first element in the list.
     */
    @Path("credentials/{credentialId}/moveAfter/{newPreviousCredentialId}")
    @POST
    public void moveCredentialAfter(final @PathParam("credentialId") String credentialId, final @PathParam("newPreviousCredentialId") String newPreviousCredentialId) {
        CredentialModel credential = userCredentialManager.getStoredCredentialById(realm, user, credentialId);
        if (credential == null) {
            throw new NotFoundException("User not found");
        }
        userCredentialManager.moveCredentialTo(realm, user, credentialId, newPreviousCredentialId);
    }

    /**
     * Send an email to the user with a link they can click to reset their password.
     * The redirectUri and clientId parameters are optional. The default for the
     * redirect is the account client.
     * <p>
     * This endpoint has been deprecated.  Please use the execute-actions-email passing a list with
     * UPDATE_PASSWORD within it.
     *
     * @param redirectUri redirect uri
     * @param clientId    client id
     */
    @Deprecated
    @Path("reset-password-email")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response resetPasswordEmail(@QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri,
                                       @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId) {
        List<String> actions = new LinkedList<>();
        actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        return executeActionsEmail(redirectUri, clientId, null, actions);
    }

    @Autowired
    private EmailTemplateProvider emailTemplateProvider;
    @Autowired
    private RedirectUtils redirectUtils;

    /**
     * Send a update account email to the user
     * <p>
     * An email contains a link the user can click to perform a set of required actions.
     * The redirectUri and clientId parameters are optional. If no redirect is given, then there will
     * be no link back to click after actions have completed.  Redirect uri must be a valid uri for the
     * particular clientId.
     *
     * @param redirectUri Redirect uri
     * @param clientId    Client id
     * @param lifespan    Number of seconds after which the generated token expires
     * @param actions     required actions the user needs to complete
     */
    @Path("execute-actions-email")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response executeActionsEmail(@QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri,
                                        @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId,
                                        @QueryParam("lifespan") Integer lifespan,
                                        List<String> actions) {
        if (user.getEmail() == null) {
            return ErrorResponse.error("User email missing", Status.BAD_REQUEST);
        }

        if (!user.isEnabled()) {
            throw new WebApplicationException(
                    ErrorResponse.error("User is disabled", Status.BAD_REQUEST));
        }

        if (redirectUri != null && clientId == null) {
            throw new WebApplicationException(
                    ErrorResponse.error("Client id missing", Status.BAD_REQUEST));
        }

        if (clientId == null) {
            clientId = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            LOG.debug("Client {} doesn't exist", clientId);
            throw new WebApplicationException(
                    ErrorResponse.error("Client doesn't exist", Status.BAD_REQUEST));
        }
        if (!client.isEnabled()) {
            LOG.debug("Client {} is not enabled", clientId);
            throw new WebApplicationException(
                    ErrorResponse.error("Client is not enabled", Status.BAD_REQUEST));
        }

        String redirect;
        if (redirectUri != null) {
            redirect = redirectUtils.verifyRedirectUri(redirectUri, client);
            if (redirect == null) {
                throw new WebApplicationException(
                        ErrorResponse.error("Invalid redirect uri.", Status.BAD_REQUEST));
            }
        }

        if (lifespan == null) {
            lifespan = realm.getActionTokenGeneratedByAdminLifespan();
        }
        int expiration = Time.currentTime() + lifespan;
        ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), expiration, actions, redirectUri, clientId);

        try {
            UriBuilder builder = LoginActionsService.actionTokenProcessor(keycloakContext.getUri());
            builder.queryParam("key", token.serialize(realm, keycloakContext.getUri()));

            String link = builder.build(realm.getName()).toString();

            this.emailTemplateProvider.setAttribute(Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions())
                    .setRealm(realm)
                    .setUser(user)
                    .sendExecuteActions(link, TimeUnit.SECONDS.toMinutes(lifespan));
            return Response.ok().build();
        } catch (EmailException e) {
//            ServicesLogger.LOGGER.failedToSendActionsEmail(e);
            return ErrorResponse.error("Failed to send execute actions email", Status.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Send an email-verification email to the user
     * <p>
     * An email contains a link the user can click to verify their email address.
     * The redirectUri and clientId parameters are optional. The default for the
     * redirect is the account client.
     *
     * @param redirectUri Redirect uri
     * @param clientId    Client id
     */
    @Path("send-verify-email")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response sendVerifyEmail(@QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri, @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId) {
        List<String> actions = new LinkedList<>();
        actions.add(UserModel.RequiredAction.VERIFY_EMAIL.name());
        return executeActionsEmail(redirectUri, clientId, null, actions);
    }

    @GET
    @Path("groups")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<GroupRepresentation> groupMembership(@QueryParam("search") String search,
                                                     @QueryParam("first") Integer firstResult,
                                                     @QueryParam("max") Integer maxResults,
                                                     @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {
        List<GroupRepresentation> results;

        if (Objects.nonNull(search) && Objects.nonNull(firstResult) && Objects.nonNull(maxResults)) {
            results = ModelToRepresentation.searchForGroupByName(user, !briefRepresentation, search.trim(), firstResult, maxResults);
        } else if (Objects.nonNull(firstResult) && Objects.nonNull(maxResults)) {
            results = ModelToRepresentation.toGroupHierarchy(user, !briefRepresentation, firstResult, maxResults);
        } else {
            results = ModelToRepresentation.toGroupHierarchy(user, !briefRepresentation);
        }

        return results;
    }

    @GET
    @NoCache
    @Path("groups/count")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Long> getGroupMembershipCount(@QueryParam("search") String search) {
        Long results;

        if (Objects.nonNull(search)) {
            results = user.getGroupsCountByNameContaining(search);
        } else {
            results = user.getGroupsCount();
        }
        Map<String, Long> map = new HashMap<>();
        map.put("count", results);
        return map;
    }

    @Autowired
    private RealmProvider realmProvider;

    @DELETE
    @Path("groups/{groupId}")
    @NoCache
    public void removeMembership(@PathParam("groupId") String groupId) {
        GroupModel group = realmProvider.getGroupById(groupId, realm);
        if (group == null) {
            throw new NotFoundException("Group not found");
        }
        try {
            if (user.isMemberOf(group)) {
                user.leaveGroup(group);
            }
        } catch (ModelException me) {
            Properties messages = adminRoot.getMessages(realm, adminAuth.getToken().getLocale());
            throw new ErrorResponseException(me.getMessage(), MessageFormat.format(messages.getProperty(me.getMessage(), me.getMessage()), me.getParameters()),
                    Status.BAD_REQUEST);
        }
    }

    @PUT
    @Path("groups/{groupId}")
    @NoCache
    public void joinGroup(@PathParam("groupId") String groupId) {
        GroupModel group = realmProvider.getGroupById(groupId, realm);
        if (group == null) {
            throw new NotFoundException("Group not found");
        }
        if (!user.isMemberOf(group)) {
            user.joinGroup(group);
        }
    }
}
