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
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource ScopeModel Mappings
 */
public class RealmScopeMappedClientResource {
    protected RealmModel realm;
    protected AdminPermissionEvaluator auth;
    protected AdminPermissionEvaluator.RequirePermissionCheck managePermission;
    protected AdminPermissionEvaluator.RequirePermissionCheck viewPermission;
    protected ScopeContainerModel scopeContainer;
    protected ClientModel scopedClient;
    protected AdminEventBuilder adminEvent;

    @Autowired
    private KeycloakContext keycloakContext;

    public RealmScopeMappedClientResource(RealmModel realm, AdminPermissionEvaluator auth, ScopeContainerModel scopeContainer, ClientModel scopedClient, AdminEventBuilder adminEvent,
                                          AdminPermissionEvaluator.RequirePermissionCheck managePermission,
                                          AdminPermissionEvaluator.RequirePermissionCheck viewPermission) {
        this.realm = realm;
        this.auth = auth;
        this.scopeContainer = scopeContainer;
        this.scopedClient = scopedClient;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT_SCOPE_MAPPING);
        this.managePermission = managePermission;
        this.viewPermission = viewPermission;
    }

    /**
     * Get the roles associated with a client's scope
     * <p>
     * Returns roles for the client.
     *
     * @return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getClientScopeMappings() {
        viewPermission.require();

        Set<RoleModel> mappings = KeycloakModelUtils.getClientScopeMappings(scopedClient, scopeContainer); //scopedClient.getClientScopeMappings(client);
        List<RoleRepresentation> mapRep = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : mappings) {
            mapRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return mapRep;
    }

    /**
     * The available client-level roles
     * <p>
     * Returns the roles for the client that can be associated with the client's scope
     *
     * @return
     */
    @Path("available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableClientScopeMappings() {
        viewPermission.require();

        Set<RoleModel> roles = scopedClient.getRoles();
        return RealmScopeMappedResource.getAvailable(auth, scopeContainer, roles);
    }

    /**
     * Get effective client roles
     * <p>
     * Returns the roles for the client that are associated with the client's scope.
     *
     * @return
     */
    @Path("composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeClientScopeMappings() {
        viewPermission.require();

        Set<RoleModel> roles = scopedClient.getRoles();
        return RealmScopeMappedResource.getComposite(scopeContainer, roles);
    }

    /**
     * Add client-level roles to the client's scope
     *
     * @param roles
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addClientScopeMapping(List<RoleRepresentation> roles) {
        managePermission.require();

        for (RoleRepresentation role : roles) {
            RoleModel roleModel = scopedClient.getRole(role.getName());
            if (roleModel == null) {
                throw new NotFoundException("Role not found");
            }
            scopeContainer.addScopeMapping(roleModel);
        }

        adminEvent.operation(OperationType.CREATE).resourcePath(keycloakContext.getUri()).representation(roles).success();
    }

    /**
     * Remove client-level roles from the client's scope.
     *
     * @param roles
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteClientScopeMapping(List<RoleRepresentation> roles) {
        managePermission.require();

        if (roles == null) {
            Set<RoleModel> roleModels = KeycloakModelUtils.getClientScopeMappings(scopedClient, scopeContainer);//scopedClient.getClientScopeMappings(client);
            roles = new LinkedList<>();

            for (RoleModel roleModel : roleModels) {
                scopeContainer.deleteScopeMapping(roleModel);
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }

        } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = scopedClient.getRole(role.getName());
                if (roleModel == null) {
                    throw new NotFoundException("Role not found");
                }
                scopeContainer.deleteScopeMapping(roleModel);
            }
        }

        adminEvent.operation(OperationType.DELETE).resourcePath(keycloakContext.getUri()).representation(roles).success();
    }
}