package org.keycloak.services.resources.account;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hsbc.unified.iam.facade.model.credential.UserCredentialModel;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.credential.*;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.messages.Messages;
import org.keycloak.utils.MediaType;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement.DISABLED;
import static org.keycloak.utils.CredentialHelper.createUserStorageCredentialRepresentation;

public class AccountCredentialResource {

    public static final String TYPE = "type";
    public static final String ENABLED_ONLY = "enabled-only";
    public static final String USER_CREDENTIALS = "user-credentials";


    @Autowired
    private KeycloakContext keycloakContext;
    private final EventBuilder event;
    private final UserModel user;
    private final RealmModel realm;
    private Auth auth;

    @Autowired
    private UserCredentialManager userCredentialManager;
    @Autowired
    private UserCredentialStoreManager userCredentialStoreManager;

    public AccountCredentialResource(EventBuilder event, UserModel user, Auth auth) {
        this.event = event;
        this.user = user;
        this.auth = auth;
        realm = keycloakContext.getRealm();
    }

    /**
     * Retrieve the list of credentials available to the current logged in user. It will return only credentials of enabled types,
     * which user can use to authenticate in some authentication flow.
     *
     * @param type            Allows to filter just single credential type, which will be specified as this parameter. If null, it will return all credential types
     * @param userCredentials specifies if user credentials should be returned. If true, they will be returned in the "userCredentials" attribute of
     *                        particular credential. Defaults to true.
     * @return
     */
    @GET
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public List<CredentialContainer> credentialTypes(@QueryParam(TYPE) String type,
                                                     @QueryParam(USER_CREDENTIALS) Boolean userCredentials) {
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);

        boolean includeUserCredentials = userCredentials == null || userCredentials;

        List<CredentialContainer> credentialTypes = new LinkedList<>();
        List<CredentialProvider> credentialProviders = userCredentialStoreManager.getCredentialProviders(realm, CredentialProvider.class);
        Set<String> enabledCredentialTypes = getEnabledCredentialTypes(credentialProviders);

        List<CredentialModel> models = includeUserCredentials ? userCredentialManager.getStoredCredentials(realm, user) : null;

        // Don't return secrets from REST endpoint
        if (models != null) {
            for (CredentialModel credential : models) {
                credential.setSecretData(null);
            }
        }

        for (CredentialProvider credentialProvider : credentialProviders) {
            String credentialProviderType = credentialProvider.getType();

            // Filter just by single type
            if (type != null && !type.equals(credentialProviderType)) {
                continue;
            }

            boolean enabled = enabledCredentialTypes.contains(credentialProviderType);

            // Filter disabled credential types
            if (!enabled) {
                continue;
            }

            CredentialTypeMetadataContext ctx = CredentialTypeMetadataContext.builder()
                    .user(user)
                    .build();
            CredentialTypeMetadata metadata = credentialProvider.getCredentialTypeMetadata(ctx);

            List<CredentialRepresentation> userCredentialModels = null;
            if (includeUserCredentials) {
                userCredentialModels = models.stream()
                        .filter(credentialModel -> credentialProvider.getType().equals(credentialModel.getType()))
                        .map(ModelToRepresentation::toRepresentation)
                        .collect(Collectors.toList());

                if (userCredentialModels.isEmpty() && userCredentialManager.isConfiguredFor(realm, user, credentialProviderType)) {
                    // In case user is federated in the userStorage, he may have credential configured on the userStorage side. We're
                    // creating "dummy" credential representing the credential provided by userStorage
                    CredentialRepresentation credential = createUserStorageCredentialRepresentation(credentialProviderType);

                    userCredentialModels = Collections.singletonList(credential);
                }

                // In case that there are no userCredentials AND there are not required actions for setup new credential,
                // we won't include credentialType as user won't be able to do anything with it
                if (userCredentialModels.isEmpty() && metadata.getCreateAction() == null && metadata.getUpdateAction() == null) {
                    continue;
                }
            }

            CredentialContainer credType = new CredentialContainer(metadata, userCredentialModels);
            credentialTypes.add(credType);
        }

        credentialTypes.sort(Comparator.comparing(CredentialContainer::getMetadata));

        return credentialTypes;
    }

    @Autowired
    private Map<String, AuthenticatorFactory> authenticatorFactories;

    // Going through all authentication flows and their authentication executions to see if there is any authenticator of the corresponding
    // credential type.
    private Set<String> getEnabledCredentialTypes(List<CredentialProvider> credentialProviders) {
        Set<String> enabledCredentialTypes = new HashSet<>();

        for (AuthenticationFlowModel flow : realm.getAuthenticationFlows()) {
            // Ignore DISABLED executions and flows
            if (isFlowEffectivelyDisabled(flow)) continue;

            for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutions(flow.getId())) {
                if (execution.getAuthenticator() != null && DISABLED != execution.getRequirement()) {
                    AuthenticatorFactory authenticatorFactory = authenticatorFactories.get(execution.getAuthenticator());
                    if (authenticatorFactory != null && authenticatorFactory.getReferenceCategory() != null) {
                        enabledCredentialTypes.add(authenticatorFactory.getReferenceCategory());
                    }
                }
            }
        }

        Set<String> credentialTypes = credentialProviders.stream()
                .map(CredentialProvider::getType)
                .collect(Collectors.toSet());

        enabledCredentialTypes.retainAll(credentialTypes);

        return enabledCredentialTypes;
    }

    // Returns true if flow is effectively disabled - either it's execution or some parent execution is disabled
    private boolean isFlowEffectivelyDisabled(AuthenticationFlowModel flow) {
        while (!flow.isTopLevel()) {
            AuthenticationExecutionModel flowExecution = realm.getAuthenticationExecutionByFlowId(flow.getId());
            if (flowExecution == null) return false; // Can happen under some corner cases
            if (DISABLED == flowExecution.getRequirement()) return true;
            if (flowExecution.getParentFlow() == null) return false;

            // Check parent flow
            flow = realm.getAuthenticationFlowById(flowExecution.getParentFlow());
            if (flow == null) return false;
        }

        return false;
    }

    /**
     * Remove a credential of current user
     *
     * @param credentialId ID of the credential, which will be removed
     */
    @Path("{credentialId}")
    @DELETE
    @NoCache
    public void removeCredential(final @PathParam("credentialId") String credentialId) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);
        userCredentialManager.removeStoredCredential(realm, user, credentialId);
    }

    /**
     * Update a user label of specified credential of current user
     *
     * @param credentialId ID of the credential, which will be updated
     * @param userLabel    new user label
     */
    @PUT
    @Consumes(javax.ws.rs.core.MediaType.TEXT_PLAIN)
    @Path("{credentialId}/label")
    public void setLabel(final @PathParam("credentialId") String credentialId, String userLabel) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);
        userCredentialManager.updateCredentialLabel(realm, user, credentialId, userLabel);
    }

    @Autowired
    private Map<String, CredentialProviderFactory> credentialProviderFactories;

    @GET
    @Path("password")
    @Produces(MediaType.APPLICATION_JSON)
    public PasswordDetails passwordDetails() throws IOException {
        auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);

        PasswordCredentialProvider passwordCredentialProvider = (PasswordCredentialProvider) credentialProviderFactories.get(PasswordCredentialProviderFactory.PROVIDER_ID);
        CredentialModel password = passwordCredentialProvider.getPassword(realm, user);

        PasswordDetails details = new PasswordDetails();
        if (password != null) {
            details.setRegistered(true);
            Long createdDate = password.getCreatedDate();
            if (createdDate != null) {
                details.setLastUpdate(createdDate);
            }
        } else {
            details.setRegistered(false);
        }

        return details;
    }

    @POST
    @Path("password")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response passwordUpdate(PasswordUpdate update) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);

        event.event(EventType.UPDATE_PASSWORD);

        UserCredentialModel cred = UserCredentialModel.password(update.getCurrentPassword());
        if (!userCredentialManager.isValid(realm, user, cred)) {
            event.error(org.keycloak.events.Errors.INVALID_USER_CREDENTIALS);
            return ErrorResponse.error(Messages.INVALID_PASSWORD_EXISTING, Response.Status.BAD_REQUEST);
        }

        if (update.getNewPassword() == null) {
            return ErrorResponse.error(Messages.INVALID_PASSWORD_EXISTING, Response.Status.BAD_REQUEST);
        }

        String confirmation = update.getConfirmation();
        if ((confirmation != null) && !update.getNewPassword().equals(confirmation)) {
            return ErrorResponse.error(Messages.NOTMATCH_PASSWORD, Response.Status.BAD_REQUEST);
        }

        try {
            userCredentialManager.updateCredential(realm, user, UserCredentialModel.password(update.getNewPassword(), false));
        } catch (ModelException e) {
            return ErrorResponse.error(e.getMessage(), e.getParameters(), Response.Status.BAD_REQUEST);
        }

        event.client(auth.getClient()).user(auth.getUser()).success();

        return Response.ok().build();
    }

    public static class CredentialContainer {
        // ** category, displayName and helptext attributes can be ordinary UI text or a key into
        //    a localized message bundle.  Typically, it will be a key, but
        //    the UI will work just fine if you don't care about localization
        //    and you want to just send UI text.
        //
        //    Also, the ${} shown in Apicurio is not needed.
        private String type;
        private String category; // **
        private String displayName;
        private String helptext;  // **
        private String iconCssClass;
        private String createAction;
        private String updateAction;
        private boolean removeable;
        private List<CredentialRepresentation> userCredentials;
        private CredentialTypeMetadata metadata;

        public CredentialContainer() {
        }

        public CredentialContainer(CredentialTypeMetadata metadata, List<CredentialRepresentation> userCredentials) {
            this.metadata = metadata;
            this.type = metadata.getType();
            this.category = metadata.getCategory().toString();
            this.displayName = metadata.getDisplayName();
            this.helptext = metadata.getHelpText();
            this.iconCssClass = metadata.getIconCssClass();
            this.createAction = metadata.getCreateAction();
            this.updateAction = metadata.getUpdateAction();
            this.removeable = metadata.isRemoveable();
            this.userCredentials = userCredentials;
        }

        public String getCategory() {
            return category;
        }

        public String getType() {
            return type;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getHelptext() {
            return helptext;
        }

        public String getIconCssClass() {
            return iconCssClass;
        }

        public String getCreateAction() {
            return createAction;
        }

        public String getUpdateAction() {
            return updateAction;
        }

        public boolean isRemoveable() {
            return removeable;
        }

        public List<CredentialRepresentation> getUserCredentials() {
            return userCredentials;
        }

        @JsonIgnore
        public CredentialTypeMetadata getMetadata() {
            return metadata;
        }
    }

    public static class PasswordDetails {

        private boolean registered;
        private long lastUpdate;

        public boolean isRegistered() {
            return registered;
        }

        public void setRegistered(boolean registered) {
            this.registered = registered;
        }

        public long getLastUpdate() {
            return lastUpdate;
        }

        public void setLastUpdate(long lastUpdate) {
            this.lastUpdate = lastUpdate;
        }

    }

    public static class PasswordUpdate {

        private String currentPassword;
        private String newPassword;
        private String confirmation;

        public String getCurrentPassword() {
            return currentPassword;
        }

        public void setCurrentPassword(String currentPassword) {
            this.currentPassword = currentPassword;
        }

        public String getNewPassword() {
            return newPassword;
        }

        public void setNewPassword(String newPassword) {
            this.newPassword = newPassword;
        }

        public String getConfirmation() {
            return confirmation;
        }

        public void setConfirmation(String confirmation) {
            this.confirmation = confirmation;
        }

    }

}
