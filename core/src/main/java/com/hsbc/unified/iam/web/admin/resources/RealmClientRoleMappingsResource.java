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
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.AdminRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Client Role Mappings
 */
public class RealmClientRoleMappingsResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientRoleMappingsResource.class);

    protected KeycloakSession session;
    protected RealmModel realm;
    protected RoleMapperModel user;
    protected ClientModel client;

    @Autowired
    private AdminRoot adminRoot;

    public RealmClientRoleMappingsResource(RealmModel realm,
                                           RoleMapperModel user,
                                           ClientModel client) {
        this.realm = realm;
        this.user = user;
        this.client = client;
    }

    public static List<RoleRepresentation> getAvailableRoles(RoleMapperModel mapper, Set<RoleModel> available) {
        Set<RoleModel> roles = new HashSet<>();
        for (RoleModel roleModel : available) {
            if (mapper.hasRole(roleModel)) continue;
            roles.add(roleModel);
        }

        List<RoleRepresentation> mappings = new ArrayList<>();
        for (RoleModel roleModel : roles) {
            mappings.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return mappings;
    }

    /**
     * Get client-level role mappings for the user, and the app
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getClientRoleMappings() {
        Set<RoleModel> mappings = user.getClientRoleMappings(client);
        List<RoleRepresentation> mapRep = new ArrayList<>();
        for (RoleModel roleModel : mappings) {
            mapRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return mapRep;
    }

    /**
     * Get effective client-level role mappings
     * <p>
     * This recurses any composite roles
     */
    @Path("composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeClientRoleMappings() {
        Set<RoleModel> roles = client.getRoles();
        List<RoleRepresentation> mapRep = new ArrayList<>();
        for (RoleModel roleModel : roles) {
            if (user.hasRole(roleModel)) mapRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return mapRep;
    }

    /**
     * Get available client-level roles that can be mapped to the user
     */
    @Path("available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableClientRoleMappings() {
        Set<RoleModel> available = client.getRoles();
        available = new HashSet<>(available);
        return getAvailableRoles(user, available);
    }

    /**
     * Add client-level roles to the user role mapping
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addClientRoleMapping(List<RoleRepresentation> roles) {
        for (RoleRepresentation role : roles) {
            RoleModel roleModel = client.getRole(role.getName());
            if (roleModel == null || !roleModel.getId().equals(role.getId())) {
                throw new NotFoundException("Role not found");
            }
            user.grantRole(roleModel);
        }
    }

    /**
     * Delete client-level roles from user role mapping
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteClientRoleMapping(List<RoleRepresentation> roles) {
        if (roles == null) {
            Set<RoleModel> roleModels = user.getClientRoleMappings(client);
            roles = new LinkedList<>();

            for (RoleModel roleModel : roleModels) {
                if (roleModel.getContainer() instanceof ClientModel) {
                    ClientModel client = (ClientModel) roleModel.getContainer();
                    if (!client.getId().equals(this.client.getId())) continue;
                }
                user.deleteRoleMapping(roleModel);
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }

        } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = client.getRole(role.getName());
                if (roleModel == null || !roleModel.getId().equals(role.getId())) {
                    throw new NotFoundException("Role not found");
                }
                try {
                    user.deleteRoleMapping(roleModel);
                } catch (ModelException me) {
                    Properties messages = adminRoot.getMessages(realm, Locale.getDefault().getLanguage());
                    throw new ErrorResponseException(me.getMessage(), MessageFormat.format(messages.getProperty(me.getMessage(), me.getMessage()), me.getParameters()),
                            Response.Status.BAD_REQUEST);
                }
            }
        }
    }
}
