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
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.ScopeContainerModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

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
    protected ScopeContainerModel scopeContainer;
    protected ClientModel scopedClient;

    public RealmScopeMappedClientResource(RealmModel realm,
                                          ScopeContainerModel scopeContainer,
                                          ClientModel scopedClient) {
        this.realm = realm;
        this.scopeContainer = scopeContainer;
        this.scopedClient = scopedClient;
    }

    /**
     * Get the roles associated with a client's scope
     * <p>
     * Returns roles for the client.
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getClientScopeMappings() {
        Set<RoleModel> mappings = KeycloakModelUtils.getClientScopeMappings(scopedClient, scopeContainer);
        List<RoleRepresentation> mapRep = new ArrayList<>();
        for (RoleModel roleModel : mappings) {
            mapRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }

        return mapRep;
    }

    /**
     * The available client-level roles
     * <p>
     * Returns the roles for the client that can be associated with the client's scope
     */
    @Path("available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableClientScopeMappings() {
        Set<RoleModel> roles = scopedClient.getRoles();
        return RealmScopeMappedResource.getAvailable(scopeContainer, roles);
    }

    /**
     * Get effective client roles
     * <p>
     * Returns the roles for the client that are associated with the client's scope.
     */
    @Path("composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeClientScopeMappings() {
        Set<RoleModel> roles = scopedClient.getRoles();
        return RealmScopeMappedResource.getComposite(scopeContainer, roles);
    }

    /**
     * Add client-level roles to the client's scope
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addClientScopeMapping(List<RoleRepresentation> roles) {
        for (RoleRepresentation role : roles) {
            RoleModel roleModel = scopedClient.getRole(role.getName());
            if (roleModel == null) {
                throw new NotFoundException("Role not found");
            }
            scopeContainer.addScopeMapping(roleModel);
        }
    }

    /**
     * Remove client-level roles from the client's scope.
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteClientScopeMapping(List<RoleRepresentation> roles) {
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
    }
}
