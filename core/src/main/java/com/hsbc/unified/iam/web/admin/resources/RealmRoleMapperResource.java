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
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.AdminRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.*;

/**
 * Base resource for managing users
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:mpaulosnunes@gmail.com">Miguel P. Nunes</a>
 * @version $Revision: 1 $
 * @resource Role Mapper
 */
public class RealmRoleMapperResource {

    protected static final Logger LOG = LoggerFactory.getLogger(RealmRoleMapperResource.class);

    protected RealmModel realm;
    @Context
    protected ClientConnection clientConnection;
    @Context
    protected KeycloakSession session;
    @Context
    protected HttpHeaders headers;
    private RoleMapperModel roleMapper;

    public RealmRoleMapperResource(RealmModel realm,
                                   RoleMapperModel roleMapper) {
        this.realm = realm;
        this.roleMapper = roleMapper;
    }

    /**
     * Get role mappings
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public MappingsRepresentation getRoleMappings() {
        List<RoleRepresentation> realmRolesRepresentation = new ArrayList<>();
        Map<String, ClientMappingsRepresentation> appMappings = new HashMap<>();

        ClientModel clientModel;
        ClientMappingsRepresentation mappings;

        for (RoleModel roleMapping : roleMapper.getRoleMappings()) {
            RoleContainerModel container = roleMapping.getContainer();
            if (container instanceof RealmModel) {
                realmRolesRepresentation.add(ModelToRepresentation.toBriefRepresentation(roleMapping));
            } else if (container instanceof ClientModel) {
                clientModel = (ClientModel) container;
                if ((mappings = appMappings.get(clientModel.getClientId())) == null) {
                    mappings = new ClientMappingsRepresentation();
                    mappings.setId(clientModel.getId());
                    mappings.setClient(clientModel.getClientId());
                    mappings.setMappings(new ArrayList<>());
                    appMappings.put(clientModel.getClientId(), mappings);
                }
                mappings.getMappings().add(ModelToRepresentation.toBriefRepresentation(roleMapping));
            }
        }

        MappingsRepresentation all = new MappingsRepresentation();
        if (!realmRolesRepresentation.isEmpty()) all.setRealmMappings(realmRolesRepresentation);
        if (!appMappings.isEmpty()) all.setClientMappings(appMappings);

        return all;
    }

    /**
     * Get realm-level role mappings
     */
    @Path("realm")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getRealmRoleMappings() {
        Set<RoleModel> realmMappings = roleMapper.getRealmRoleMappings();
        List<RoleRepresentation> realmMappingsRep = new ArrayList<>();
        for (RoleModel roleModel : realmMappings) {
            realmMappingsRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
        }
        return realmMappingsRep;
    }

    /**
     * Get effective realm-level role mappings
     * <p>
     * This will recurse all composite roles to get the result.
     */
    @Path("realm/composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeRealmRoleMappings() {
        Set<RoleModel> roles = realm.getRoles();
        List<RoleRepresentation> realmMappingsRep = new ArrayList<>();
        for (RoleModel roleModel : roles) {
            if (roleMapper.hasRole(roleModel)) {
                realmMappingsRep.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }
        }

        return realmMappingsRep;
    }

    /**
     * Get realm-level roles that can be mapped
     */
    @Path("realm/available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableRealmRoleMappings() {
        Set<RoleModel> available = realm.getRoles();
        Set<RoleModel> set = new HashSet<>(available);
        return RealmClientRoleMappingsResource.getAvailableRoles(roleMapper, set);
    }

    /**
     * Add realm-level role mappings to the user
     *
     * @param roles Roles to add
     */
    @Path("realm")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addRealmRoleMappings(List<RoleRepresentation> roles) {
        LOG.debug("** addRealmRoleMappings: {}", roles);

        for (RoleRepresentation role : roles) {
            RoleModel roleModel = realm.getRole(role.getName());
            if (roleModel == null || !roleModel.getId().equals(role.getId())) {
                throw new NotFoundException("Role not found");
            }
            roleMapper.grantRole(roleModel);
        }
    }

    /**
     * Delete realm-level role mappings
     */
    @Path("realm")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteRealmRoleMappings(List<RoleRepresentation> roles) {
        LOG.debug("deleteRealmRoleMappings");
        if (roles == null) {
            Set<RoleModel> roleModels = roleMapper.getRealmRoleMappings();
            roles = new LinkedList<>();

            for (RoleModel roleModel : roleModels) {
                roleMapper.deleteRoleMapping(roleModel);
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }

        } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = realm.getRole(role.getName());
                if (roleModel == null || !roleModel.getId().equals(role.getId())) {
                    throw new NotFoundException("Role not found");
                }
                try {
                    roleMapper.deleteRoleMapping(roleModel);
                } catch (ModelException me) {
                    Properties messages = adminRoot.getMessages(realm, Locale.getDefault().getLanguage());
                    throw new ErrorResponseException(me.getMessage(), MessageFormat.format(messages.getProperty(me.getMessage(), me.getMessage()), me.getParameters()),
                            Response.Status.BAD_REQUEST);
                }
            }

        }
    }

    @Path("clients/{client}")
    public RealmClientRoleMappingsResource getUserClientRoleMappingsResource(@PathParam("client") String client) {
        ClientModel clientModel = realm.getClientById(client);
        if (clientModel == null) {
            throw new NotFoundException("Client not found");
        }

        return new RealmClientRoleMappingsResource(realm, roleMapper, clientModel);
    }

    @Autowired
    private AdminRoot adminRoot;
}
