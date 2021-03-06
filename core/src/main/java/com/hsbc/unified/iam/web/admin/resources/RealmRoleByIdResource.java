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
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;
import java.util.Set;

/**
 * Sometimes its easier to just interact with roles by their ID instead of container/role-name
 * <p>
 * Path for managing all realm-level or client-level roles defined in this realm by its id.
 * </p>
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/roles-by-id",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmRoleByIdResource extends AbstractRoleResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmRoleByIdResource.class);
    private final RealmModel realm;

    public RealmRoleByIdResource(RealmModel realm) {
        super(realm);

        this.realm = realm;
    }

    public static ManagementPermissionReference toMgmtRef(RoleModel role, AdminPermissionManagement permissions) {
        ManagementPermissionReference ref = new ManagementPermissionReference();
        ref.setEnabled(true);
        ref.setResource(permissions.roles().resource(role).getId());
        ref.setScopePermissions(permissions.roles().getPermissions(role));
        return ref;
    }

    /**
     * Get a specific role's representation
     *
     * @param id id of role
     */
    @Path("{role-id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public RoleRepresentation getRole(final @PathParam("role-id") String id) {
        RoleModel roleModel = getRoleModel(id);
        return getRole(roleModel);
    }

    protected RoleModel getRoleModel(String id) {
        RoleModel roleModel = realm.getRoleById(id);
        if (roleModel == null) {
            throw new NotFoundException("Could not find role with id");
        }
        return roleModel;
    }

    /**
     * Delete the role
     *
     * @param id id of role
     */
    @Path("{role-id}")
    @DELETE
    @NoCache
    public void deleteRole(final @PathParam("role-id") String id) {
        RoleModel role = getRoleModel(id);
        deleteRole(role);
    }

    /**
     * Update the role
     *
     * @param id id of role
     */
    @Path("{role-id}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateRole(final @PathParam("role-id") String id, final RoleRepresentation rep) {
        RoleModel role = getRoleModel(id);
        updateRole(rep, role);
    }

    /**
     * Make the role a composite role by associating some child roles
     */
    @Path("{role-id}/composites")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addComposites(final @PathParam("role-id") String id, List<RoleRepresentation> roles) {
        RoleModel role = getRoleModel(id);
        addComposites(roles, role);
    }

    /**
     * Get role's children
     * <p>
     * Returns a set of role's children provided the role is a composite.
     */
    @Path("{role-id}/composites")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRoleComposites(final @PathParam("role-id") String id) {

        if (LOG.isDebugEnabled()) LOG.debug("*** getRoleComposites: '" + id + "'");
        RoleModel role = getRoleModel(id);
        return getRoleComposites(role);
    }

    /**
     * Get realm-level roles that are in the role's composite
     */
    @Path("{role-id}/composites/realm")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRealmRoleComposites(final @PathParam("role-id") String id) {
        RoleModel role = getRoleModel(id);
        return getRealmRoleComposites(role);
    }

    /**
     * Get client-level roles for the client that are in the role's composite
     */
    @Path("{role-id}/composites/clients/{client}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getClientRoleComposites(final @PathParam("role-id") String id,
                                                           final @PathParam("client") String client) {
        RoleModel role = getRoleModel(id);
        ClientModel clientModel = realm.getClientById(client);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client");
        }
        return getClientRoleComposites(clientModel, role);
    }

    /**
     * Remove a set of roles from the role's composite
     *
     * @param id    Role id
     * @param roles A set of roles to be removed
     */
    @Path("{role-id}/composites")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteComposites(final @PathParam("role-id") String id, List<RoleRepresentation> roles) {
        RoleModel role = getRoleModel(id);
        deleteComposites(roles, role);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     */
    @Path("{role-id}/management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions(final @PathParam("role-id") String id) {
        RoleModel role = getRoleModel(id);

        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (!permissions.roles().isPermissionsEnabled(role)) {
            return new ManagementPermissionReference();
        }
        return toMgmtRef(role, permissions);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     *
     * @return initialized manage permissions reference
     */
    @Path("{role-id}/management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(final @PathParam("role-id") String id, ManagementPermissionReference ref) {
        RoleModel role = getRoleModel(id);

        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.roles().setPermissionsEnabled(role, ref.isEnabled());
        if (ref.isEnabled()) {
            return toMgmtRef(role, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }
}
