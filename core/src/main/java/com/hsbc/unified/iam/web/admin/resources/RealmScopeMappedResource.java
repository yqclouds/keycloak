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

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.*;

/**
 * Base class for managing the scope mappings of a specific client.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource ScopeModel Mappings
 */
public class RealmScopeMappedResource {
    protected RealmModel realm;
    protected AdminPermissionEvaluator auth;
    protected AdminPermissionEvaluator.RequirePermissionCheck managePermission;
    protected AdminPermissionEvaluator.RequirePermissionCheck viewPermission;

    protected ScopeContainerModel scopeContainer;
    protected AdminEventBuilder adminEvent;

    @Autowired
    private KeycloakContext keycloakContext;

    public RealmScopeMappedResource(RealmModel realm, AdminPermissionEvaluator auth, ScopeContainerModel scopeContainer,
                                    AdminEventBuilder adminEvent,
                                    AdminPermissionEvaluator.RequirePermissionCheck managePermission,
                                    AdminPermissionEvaluator.RequirePermissionCheck viewPermission) {
        this.realm = realm;
        this.auth = auth;
        this.scopeContainer = scopeContainer;
        this.adminEvent = adminEvent.resource(ResourceType.REALM_SCOPE_MAPPING);
        this.managePermission = managePermission;
        this.viewPermission = viewPermission;
    }

    public static List<RoleRepresentation> getAvailable(AdminPermissionEvaluator auth, ScopeContainerModel client, Set<RoleModel> roles) {
        List<RoleRepresentation> available = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : roles) {
            if (client.hasScope(roleModel)) continue;
            if (!auth.roles().canMapClientScope(roleModel)) continue;
            available.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return available;
    }

    public static List<RoleRepresentation> getComposite(ScopeContainerModel client, Set<RoleModel> roles) {
        List<RoleRepresentation> composite = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : roles) {
            if (client.hasScope(roleModel)) composite.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return composite;
    }

    /**
     * Get all scope mappings for the client
     *
     * @return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public MappingsRepresentation getScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        MappingsRepresentation all = new MappingsRepresentation();
        Set<RoleModel> realmMappings = scopeContainer.getRealmScopeMappings();
        if (realmMappings.size() > 0) {
            List<RoleRepresentation> realmRep = new ArrayList<RoleRepresentation>();
            for (RoleModel roleModel : realmMappings) {
                realmRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }
            all.setRealmMappings(realmRep);
        }

        List<ClientModel> clients = realm.getClients();
        if (clients.size() > 0) {
            Map<String, ClientMappingsRepresentation> clientMappings = new HashMap<String, ClientMappingsRepresentation>();
            for (ClientModel client : clients) {
                Set<RoleModel> roleMappings = KeycloakModelUtils.getClientScopeMappings(client, this.scopeContainer); //client.getClientScopeMappings(this.client);
                if (roleMappings.size() > 0) {
                    ClientMappingsRepresentation mappings = new ClientMappingsRepresentation();
                    mappings.setId(client.getId());
                    mappings.setClient(client.getClientId());
                    List<RoleRepresentation> roles = new ArrayList<RoleRepresentation>();
                    mappings.setMappings(roles);
                    for (RoleModel role : roleMappings) {
                        roles.add(ModelToRepresentation.toBriefRepresentation(role));
                    }
                    clientMappings.put(client.getClientId(), mappings);
                    all.setClientMappings(clientMappings);
                }
            }
        }
        return all;
    }

    /**
     * Get realm-level roles associated with the client's scope
     *
     * @return
     */
    @Path("realm")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> realmMappings = scopeContainer.getRealmScopeMappings();
        List<RoleRepresentation> realmMappingsRep = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : realmMappings) {
            realmMappingsRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return realmMappingsRep;
    }

    /**
     * Get realm-level roles that are available to attach to this client's scope
     *
     * @return
     */
    @Path("realm/available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> roles = realm.getRoles();
        return getAvailable(auth, scopeContainer, roles);
    }

    /**
     * Get effective realm-level roles associated with the client's scope
     * <p>
     * What this does is recurse
     * any composite roles associated with the client's scope and adds the roles to this lists.  The method is really
     * to show a comprehensive total view of realm-level roles associated with the client.
     *
     * @return
     */
    @Path("realm/composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> roles = realm.getRoles();
        return getComposite(scopeContainer, roles);
    }

    /**
     * Add a set of realm-level roles to the client's scope
     *
     * @param roles
     */
    @Path("realm")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addRealmScopeMappings(List<RoleRepresentation> roles) {
        managePermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        for (RoleRepresentation role : roles) {
            RoleModel roleModel = realm.getRoleById(role.getId());
            if (roleModel == null) {
                throw new NotFoundException("Role not found");
            }
            scopeContainer.addScopeMapping(roleModel);
        }

        adminEvent.operation(OperationType.CREATE).resourcePath(keycloakContext.getUri()).representation(roles).success();
    }

    /**
     * Remove a set of realm-level roles from the client's scope
     *
     * @param roles
     */
    @Path("realm")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteRealmScopeMappings(List<RoleRepresentation> roles) {
        managePermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        if (roles == null) {
            Set<RoleModel> roleModels = scopeContainer.getRealmScopeMappings();
            roles = new LinkedList<>();

            for (RoleModel roleModel : roleModels) {
                scopeContainer.deleteScopeMapping(roleModel);
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }

        } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = realm.getRoleById(role.getId());
                if (roleModel == null) {
                    throw new NotFoundException("Client not found");
                }
                scopeContainer.deleteScopeMapping(roleModel);
            }
        }

        adminEvent.operation(OperationType.DELETE).resourcePath(keycloakContext.getUri()).representation(roles).success();

    }

    @Path("clients/{client}")
    public RealmScopeMappedClientResource getClientByIdScopeMappings(@PathParam("client") String client) {
        ClientModel clientModel = realm.getClientById(client);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client");
        }
        return new RealmScopeMappedClientResource(realm, auth, this.scopeContainer, clientModel, adminEvent, managePermission, viewPermission);
    }
}