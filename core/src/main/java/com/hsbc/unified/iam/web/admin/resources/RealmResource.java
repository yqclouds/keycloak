package com.hsbc.unified.iam.web.admin.resources;

import com.fasterxml.jackson.core.type.TypeReference;
import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import com.hsbc.unified.iam.web.convert.converter.ClientDescriptionConverter;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.Config;
import org.keycloak.KeyPairVerifier;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.exportimport.util.ExportOptions;
import org.keycloak.exportimport.util.ExportUtils;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.StripSecretsUtils;
import org.keycloak.partialimport.PartialImportManager;
import org.keycloak.representations.adapters.action.GlobalRequestResult;
import org.keycloak.representations.idm.*;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.LDAPConnectionTestManager;
import org.keycloak.services.managers.ResourceAdminManager;
import org.keycloak.services.managers.UserStorageSyncManager;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.utils.ReservedCharValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.hsbc.unified.iam.core.util.JsonSerialization.readValue;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}",
        consumes = {MediaType.APPLICATION_JSON_VALUE},
        produces = {MediaType.APPLICATION_JSON_VALUE}
)
public class RealmResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmResource.class);

    @Autowired
    private RealmFacadeImpl realmFacade;

    @Autowired
    private List<ClientDescriptionConverter> clientDescriptionConverters;

    @ResponseStatus(value = HttpStatus.CONFLICT, reason = "Realm not found")
    @ExceptionHandler(NotFoundException.class)
    public void handleNotFoundException(NotFoundException e) {
        LOG.error("Realm not found", e);
    }

    @ResponseStatus(value = HttpStatus.CONFLICT)
    @ExceptionHandler(BadRequestException.class)
    public void handleBadRequestException(BadRequestException e) {
        LOG.error("Unsupported format", e);
    }

    /**
     * Base path for importing clients under this realm.
     */
    @RequestMapping(
            value = "/client-description-converter",
            consumes = {
                    MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_PLAIN_VALUE
            },
            method = RequestMethod.POST
    )
    @PreAuthorize("hasPermission({'master', 'admin', 'manage-clients'})")
    public ClientRepresentation getImportClientRepresentation(@PathVariable("realm") final String name, String content) {
        RealmModel realm = checkRealm(name);

        for (ClientDescriptionConverter converter : clientDescriptionConverters) {
            if (converter.supports(content)) {
                return converter.convert(content);
            }
        }

        throw new BadRequestException("Unsupported format");
    }

    private RealmModel checkRealm(final String name) throws NotFoundException, BadRequestException {
        RealmModel result = realmFacade.getRealmByName(name);
        if (result == null) throw new NotFoundException("Realm not found.");

        return result;
    }

    protected AdminPermissionEvaluator auth;
    protected RealmModel realm;
    @Context
    protected ClientConnection connection;
    @Context
    protected HttpHeaders headers;
    private AdminEventBuilder adminEvent;

    @Autowired
    private StripSecretsUtils stripSecretsUtils;
    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private UserSessionProvider userSessionProvider;
    @Autowired
    private Map<String, RequiredActionProvider> requiredActionProviders;

    public RealmResource(AdminPermissionEvaluator auth, RealmModel realm, AdminEventBuilder adminEvent) {
        this.auth = auth;
        this.realm = realm;
        this.adminEvent = adminEvent.realm(realm).resource(ResourceType.REALM);
    }

    /**
     * Get the top-level representation of the realm
     * <p>
     * It will not include nested information like User and Client representations.
     */
    @RequestMapping(method = RequestMethod.GET)
    public RealmRepresentation getRealm() {
        if (auth.realm().canViewRealm()) {
            return ModelToRepresentation.toRepresentation(realm, false);
        } else {
            auth.realm().requireViewRealmNameList();

            RealmRepresentation rep = new RealmRepresentation();
            rep.setRealm(realm.getName());

            if (auth.realm().canViewIdentityProviders()) {
                RealmRepresentation r = ModelToRepresentation.toRepresentation(realm, false);
                rep.setIdentityProviders(r.getIdentityProviders());
                rep.setIdentityProviderMappers(r.getIdentityProviderMappers());
            }

            return rep;
        }
    }

    /**
     * Update the top-level information of the realm
     * <p>
     * Any user, roles or client information in the representation
     * will be ignored.  This will only update top-level attributes of the realm.
     */
    @RequestMapping(method = RequestMethod.PUT)
    public Response updateRealm(final RealmRepresentation rep) {
        auth.realm().requireManageRealm();

        LOG.debug("updating realm: " + realm.getName());

        if (Config.getAdminRealm().equals(realm.getName()) && (rep.getRealm() != null && !rep.getRealm().equals(Config.getAdminRealm()))) {
            return ErrorResponse.error("Can't rename master realm", Response.Status.BAD_REQUEST);
        }

        ReservedCharValidator.validate(rep.getRealm());

        try {
            if (!Constants.GENERATE.equals(rep.getPublicKey()) && (rep.getPrivateKey() != null && rep.getPublicKey() != null)) {
                try {
                    KeyPairVerifier.verify(rep.getPrivateKey(), rep.getPublicKey());
                } catch (VerificationException e) {
                    return ErrorResponse.error(e.getMessage(), Response.Status.BAD_REQUEST);
                }
            }

            if (!Constants.GENERATE.equals(rep.getPublicKey()) && (rep.getCertificate() != null)) {
                try {
                    X509Certificate cert = PemUtils.decodeCertificate(rep.getCertificate());
                    if (cert == null) {
                        return ErrorResponse.error("Failed to decode certificate", Response.Status.BAD_REQUEST);
                    }
                } catch (Exception e) {
                    return ErrorResponse.error("Failed to decode certificate", Response.Status.BAD_REQUEST);
                }
            }

            representationToModel.updateRealm(rep, realm);

            // Refresh periodic sync tasks for configured federationProviders
            List<UserStorageProviderModel> federationProviders = realm.getUserStorageProviders();
            UserStorageSyncManager usersSyncManager = new UserStorageSyncManager();
            for (final UserStorageProviderModel fedProvider : federationProviders) {
                usersSyncManager.notifyToRefreshPeriodicSync(realm, fedProvider, false);
            }

            adminEvent.operation(OperationType.UPDATE).representation(StripSecretsUtils.strip(rep)).success();

            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Realm with same name exists");
        } catch (ModelException e) {
            return ErrorResponse.error(e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return ErrorResponse.error("Failed to update realm", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Delete the realm
     */
    @RequestMapping(method = RequestMethod.DELETE)
    public void deleteRealm() {
        auth.realm().requireManageRealm();

        if (!new RealmFacadeImpl().removeRealm(realm)) {
            throw new NotFoundException("Realm doesn't exist");
        }
    }

    /**
     * Push the realm's revocation policy to any client that has an admin url associated with it.
     */
    @Path("push-revocation")
    @POST
    public GlobalRequestResult pushRevocation() {
        auth.realm().requireManageRealm();

        GlobalRequestResult result = new ResourceAdminManager().pushRealmRevocationPolicy(realm);
        adminEvent.operation(OperationType.ACTION).resourcePath(keycloakContext.getUri()).representation(result).success();
        return result;
    }

    /**
     * Removes all user sessions.  Any client that has an admin url will also be told to invalidate any sessions
     * they have.
     */
    @Path("logout-all")
    @POST
    public GlobalRequestResult logoutAll() {
        auth.users().requireManage();

        userSessionProvider.removeUserSessions(realm);
        GlobalRequestResult result = new ResourceAdminManager().logoutAll(realm);
        adminEvent.operation(OperationType.ACTION).resourcePath(keycloakContext.getUri()).representation(result).success();
        return result;
    }

    /**
     * Remove a specific user session. Any client that has an admin url will also be told to invalidate this
     * particular session.
     *
     * @param sessionId
     */
    @Path("sessions/{session}")
    @DELETE
    public void deleteSession(@PathParam("session") String sessionId) {
        auth.users().requireManage();

        UserSessionModel userSession = userSessionProvider.getUserSession(realm, sessionId);
        if (userSession == null) throw new NotFoundException("Sesssion not found");
        authenticationManager.backchannelLogout(realm, userSession, keycloakContext.getUri(), connection, headers, true);
        adminEvent.operation(OperationType.DELETE).resource(ResourceType.USER_SESSION).resourcePath(keycloakContext.getUri()).success();
    }

    /**
     * Get client session stats
     * <p>
     * Returns a JSON map.  The key is the client id, the value is the number of sessions that currently are active
     * with that client.  Only clients that actually have a session associated with them will be in this map.
     *
     * @return
     */
    @Path("client-session-stats")
    @GET
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public List<Map<String, String>> getClientSessionStats() {
        auth.realm().requireViewRealm();

        Map<String, Map<String, String>> data = new HashMap<>();
        {
            Map<String, Long> activeCount = userSessionProvider.getActiveClientSessionStats(realm, false);
            for (Map.Entry<String, Long> entry : activeCount.entrySet()) {
                Map<String, String> map = new HashMap<>();
                ClientModel client = realm.getClientById(entry.getKey());
                if (client == null)
                    continue;
                map.put("id", client.getId());
                map.put("clientId", client.getClientId());
                map.put("active", entry.getValue().toString());
                map.put("offline", "0");
                data.put(client.getId(), map);
            }
        }
        {
            Map<String, Long> offlineCount = userSessionProvider.getActiveClientSessionStats(realm, true);
            for (Map.Entry<String, Long> entry : offlineCount.entrySet()) {
                Map<String, String> map = data.get(entry.getKey());
                if (map == null) {
                    map = new HashMap<>();
                    ClientModel client = realm.getClientById(entry.getKey());
                    if (client == null)
                        continue;
                    map.put("id", client.getId());
                    map.put("clientId", client.getClientId());
                    map.put("active", "0");
                    data.put(client.getId(), map);
                }
                map.put("offline", entry.getValue().toString());
            }
        }
        List<Map<String, String>> result = new LinkedList<>();
        for (Map<String, String> item : data.values())
            result.add(item);
        return result;
    }

    /**
     * Test LDAP connection
     *
     * @param action
     * @param connectionUrl
     * @param bindDn
     * @param bindCredential
     * @return
     */
    @Path("testLDAPConnection")
    @POST
    @NoCache
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    @Deprecated
    public Response testLDAPConnection(@FormParam("action") String action, @FormParam("connectionUrl") String connectionUrl,
                                       @FormParam("bindDn") String bindDn, @FormParam("bindCredential") String bindCredential,
                                       @FormParam("useTruststoreSpi") String useTruststoreSpi, @FormParam("connectionTimeout") String connectionTimeout,
                                       @FormParam("componentId") String componentId, @FormParam("startTls") String startTls) {
        auth.realm().requireManageRealm();

        if (componentId != null && bindCredential.equals(ComponentRepresentation.SECRET_VALUE)) {
            bindCredential = realm.getComponent(componentId).getConfig().getFirst(LDAPConstants.BIND_CREDENTIAL);
        }

        boolean result = LDAPConnectionTestManager.testLDAP(action, connectionUrl, bindDn, bindCredential, useTruststoreSpi, connectionTimeout, startTls);
        return result ? Response.noContent().build() : ErrorResponse.error("LDAP test error", Response.Status.BAD_REQUEST);
    }

    /**
     * Test LDAP connection
     *
     * @return
     */
    @Path("testLDAPConnection")
    @POST
    @NoCache
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public Response testLDAPConnection(TestLdapConnectionRepresentation config) {
        return testLDAPConnection(
                config.getAction(),
                config.getConnectionUrl(),
                config.getBindDn(),
                config.getBindCredential(),
                config.getUseTruststoreSpi(),
                config.getConnectionTimeout(),
                config.getComponentId(),
                config.getStartTls());
    }

    /**
     * Test SMTP connection with current logged in user
     *
     * @param config SMTP server configuration
     * @return
     * @throws Exception
     */
    @Path("testSMTPConnection")
    @POST
    @NoCache
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    @Deprecated
    public Response testSMTPConnection(final @FormParam("config") String config) throws Exception {
        Map<String, String> settings = readValue(config, new TypeReference<Map<String, String>>() {
        });
        return testSMTPConnection(settings);
    }

    @Autowired
    private EmailTemplateProvider emailTemplateProvider;

    @Path("testSMTPConnection")
    @POST
    @NoCache
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public Response testSMTPConnection(Map<String, String> settings) throws Exception {
        try {
            UserModel user = auth.adminAuth().getUser();
            if (user.getEmail() == null) {
                return ErrorResponse.error("Logged in user does not have an e-mail.", Response.Status.INTERNAL_SERVER_ERROR);
            }
            if (ComponentRepresentation.SECRET_VALUE.equals(settings.get("password"))) {
                settings.put("password", realm.getSmtpConfig().get("password"));
            }
            emailTemplateProvider.sendSmtpTestEmail(settings, user);
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Failed to send email \n {}", e.getCause());
            return ErrorResponse.error("Failed to send email", Response.Status.INTERNAL_SERVER_ERROR);
        }

        return Response.noContent().build();
    }

    /**
     * Get group hierarchy.  Only name and ids are returned.
     */
    @GET
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    @Path("default-groups")
    public List<GroupRepresentation> getDefaultGroups() {
        auth.realm().requireViewRealm();

        List<GroupRepresentation> defaults = new LinkedList<>();
        for (GroupModel group : realm.getDefaultGroups()) {
            defaults.add(ModelToRepresentation.toRepresentation(group, false));
        }
        return defaults;
    }

    @PUT
    @NoCache
    @Path("default-groups/{groupId}")
    public void addDefaultGroup(@PathParam("groupId") String groupId) {
        auth.realm().requireManageRealm();

        GroupModel group = realm.getGroupById(groupId);
        if (group == null) {
            throw new NotFoundException("Group not found");
        }
        realm.addDefaultGroup(group);

        adminEvent.operation(OperationType.CREATE).resource(ResourceType.GROUP).resourcePath(keycloakContext.getUri()).success();
    }

    @DELETE
    @NoCache
    @Path("default-groups/{groupId}")
    public void removeDefaultGroup(@PathParam("groupId") String groupId) {
        auth.realm().requireManageRealm();

        GroupModel group = realm.getGroupById(groupId);
        if (group == null) {
            throw new NotFoundException("Group not found");
        }
        realm.removeDefaultGroup(group);

        adminEvent.operation(OperationType.DELETE).resource(ResourceType.GROUP).resourcePath(keycloakContext.getUri()).success();
    }

    @GET
    @Path("group-by-path/{path: .*}")
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public GroupRepresentation getGroupByPath(@PathParam("path") String path) {
        GroupModel found = KeycloakModelUtils.findGroupByPath(realm, path);
        if (found == null) {
            throw new NotFoundException("Group path does not exist");

        }
        auth.groups().requireView(found);
        return ModelToRepresentation.toGroupHierarchy(found, true);
    }

    /**
     * Partial import from a JSON file to an existing realm.
     *
     * @param rep
     * @return
     */
    @Path("partialImport")
    @POST
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public Response partialImport(PartialImportRepresentation rep) {
        auth.realm().requireManageRealm();

        PartialImportManager partialImport = new PartialImportManager(rep, realm, adminEvent);
        return partialImport.saveResources();
    }

    @Autowired
    private ExportUtils exportUtils;

    /**
     * Partial export of existing realm into a JSON file.
     */
    @Path("partial-export")
    @POST
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public RealmRepresentation partialExport(@QueryParam("exportGroupsAndRoles") Boolean exportGroupsAndRoles,
                                             @QueryParam("exportClients") Boolean exportClients) {
        auth.realm().requireViewRealm();

        boolean groupsAndRolesExported = exportGroupsAndRoles != null && exportGroupsAndRoles;
        boolean clientsExported = exportClients != null && exportClients;

        if (groupsAndRolesExported) {
            auth.groups().requireList();
        }
        if (clientsExported) {
            auth.clients().requireView();
        }

        // service accounts are exported if the clients are exported
        // this means that if clients is true but groups/roles is false the service account is exported without roles
        // the other option is just include service accounts if clientsExported && groupsAndRolesExported
        ExportOptions options = new ExportOptions(false, clientsExported, groupsAndRolesExported, clientsExported);
        RealmRepresentation rep = exportUtils.exportRealm(realm, options, false);
        return stripSecretsUtils.stripForExport(rep);
    }

    /**
     * Clear realm cache
     */
    @Path("clear-realm-cache")
    @POST
    public void clearRealmCache() {
        auth.realm().requireManageRealm();
        adminEvent.operation(OperationType.ACTION).resourcePath(keycloakContext.getUri()).success();
    }

    /**
     * Clear user cache
     */
    @Path("clear-user-cache")
    @POST
    public void clearUserCache() {
        auth.realm().requireManageRealm();

        adminEvent.operation(OperationType.ACTION).resourcePath(keycloakContext.getUri()).success();
    }

    @Autowired(required = false)
    private PublicKeyStorageProvider publicKeyStorageProvider;

    /**
     * Clear cache of external public keys (Public keys of clients or Identity providers)
     */
    @Path("clear-keys-cache")
    @POST
    public void clearKeysCache() {
        auth.realm().requireManageRealm();

        if (publicKeyStorageProvider != null) {
            publicKeyStorageProvider.clearCache();
        }

        adminEvent.operation(OperationType.ACTION).resourcePath(keycloakContext.getUri()).success();
    }

    @GET
    @Path("credential-registrators")
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public List<String> getCredentialRegistrators() {
        auth.realm().requireViewRealm();
        return keycloakContext.getRealm().getRequiredActionProviders().stream()
                .filter(ra -> ra.isEnabled())
                .map(RequiredActionProviderModel::getProviderId)
                .filter(providerId -> requiredActionProviders.get(providerId) instanceof CredentialRegistrator)
                .collect(Collectors.toList());
    }
}
