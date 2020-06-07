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

import com.hsbc.unified.iam.core.constants.Constants;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.utils.ReservedCharValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * base path for managing realm-level roles of this realm
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/roles",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmRolesResource extends AbstractRoleResource {
    private final RealmModel realm;
    protected AdminPermissionEvaluator auth;

    protected RoleContainerModel roleContainer;
    private UriInfo uriInfo;

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    @Autowired
    private UserProvider userProvider;
    @Autowired
    private RealmProvider realmProvider;

    public RealmRolesResource(UriInfo uriInfo,
                              RealmModel realm,
                              AdminPermissionEvaluator auth,
                              RoleContainerModel roleContainer) {
        super(realm);
        this.uriInfo = uriInfo;
        this.realm = realm;
        this.auth = auth;
        this.roleContainer = roleContainer;
    }

    /**
     * Get all roles for the realm or client
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<RoleRepresentation> getRoles(@QueryParam("search") @DefaultValue("") String search,
                                             @QueryParam("first") Integer firstResult,
                                             @QueryParam("max") Integer maxResults,
                                             @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {
        auth.roles().requireList(roleContainer);

        Set<RoleModel> roleModels;

        if (search != null && search.trim().length() > 0) {
            roleModels = roleContainer.searchForRoles(search, firstResult, maxResults);
        } else if (!Objects.isNull(firstResult) && !Objects.isNull(maxResults)) {
            roleModels = roleContainer.getRoles(firstResult, maxResults);
        } else {
            roleModels = roleContainer.getRoles();
        }

        List<RoleRepresentation> roles = new ArrayList<>();
        for (RoleModel roleModel : roleModels) {
            if (briefRepresentation) {
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            } else {
                roles.add(ModelToRepresentation.toRepresentation(roleModel));
            }
        }
        return roles;
    }

    /**
     * Create a new role for the realm or client
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createRole(final RoleRepresentation rep) {
        auth.roles().requireManage(roleContainer);

        if (rep.getName() == null) {
            throw new BadRequestException();
        }

        ReservedCharValidator.validate(rep.getName());

        try {
            RoleModel role = roleContainer.addRole(rep.getName());
            role.setDescription(rep.getDescription());

            rep.setId(role.getId());

            return Response.created(uriInfo.getAbsolutePathBuilder().path(role.getName()).build()).build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Role with name " + rep.getName() + " already exists");
        }
    }

    /**
     * Get a role by name
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public RoleRepresentation getRole(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);

        RoleModel roleModel = roleContainer.getRole(roleName);
        if (roleModel == null) {
            throw new NotFoundException("Could not find role");
        }

        return getRole(roleModel);
    }

    /**
     * Delete a role by name
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}")
    @DELETE
    @NoCache
    public void deleteRole(final @PathParam("role-name") String roleName) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        deleteRole(role);
    }

    /**
     * Update a role by name
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateRole(final @PathParam("role-name") String roleName, final RoleRepresentation rep) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        try {
            updateRole(rep, role);

            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Role with name " + rep.getName() + " already exists");
        }
    }

    /**
     * Add a composite to the role
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}/composites")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addComposites(final @PathParam("role-name") String roleName, List<RoleRepresentation> roles) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        addComposites(auth, roles, role);
    }

    /**
     * Get composites of the role
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}/composites")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRoleComposites(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        return getRoleComposites(role);
    }

    /**
     * Get realm-level roles of the role's composite
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}/composites/realm")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRealmRoleComposites(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        return getRealmRoleComposites(role);
    }

    /**
     * An app-level roles for the specified app for the role's composite
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}/composites/clients/{client}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getClientRoleComposites(final @PathParam("role-name") String roleName,
                                                           final @PathParam("client") String client) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        ClientModel clientModel = realm.getClientById(client);
        if (client == null) {
            throw new NotFoundException("Could not find client");

        }
        return getClientRoleComposites(clientModel, role);
    }


    /**
     * Remove roles from the role's composite
     *
     * @param roleName role's name (not id!)
     * @param roles    roles to remove
     */
    @Path("{role-name}/composites")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteComposites(
            final @PathParam("role-name") String roleName,
            List<RoleRepresentation> roles) {

        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        deleteComposites(roles, role);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     */
    @Path("{role-name}/management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (!permissions.roles().isPermissionsEnabled(role)) {
            return new ManagementPermissionReference();
        }
        return RealmRoleByIdResource.toMgmtRef(role, permissions);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     *
     * @return initialized manage permissions reference
     */
    @Path("{role-name}/management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(final @PathParam("role-name") String roleName, ManagementPermissionReference ref) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.roles().setPermissionsEnabled(role, ref.isEnabled());
        if (ref.isEnabled()) {
            return RealmRoleByIdResource.toMgmtRef(role, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

    /**
     * Return List of Users that have the specified role name
     *
     * @return initialized manage permissions reference
     */
    @Path("{role-name}/users")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<UserRepresentation> getUsersInRole(final @PathParam("role-name") String roleName,
                                                   @QueryParam("first") Integer firstResult,
                                                   @QueryParam("max") Integer maxResults) {

        auth.roles().requireView(roleContainer);
        firstResult = firstResult != null ? firstResult : 0;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;

        RoleModel role = roleContainer.getRole(roleName);

        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        List<UserRepresentation> results = new ArrayList<>();
        List<UserModel> userModels = userProvider.getRoleMembers(realm, role, firstResult, maxResults);

        for (UserModel user : userModels) {
            results.add(modelToRepresentation.toRepresentation(realm, user));
        }
        return results;

    }

    /**
     * Return List of Groups that have the specified role name
     *
     * @param briefRepresentation if false, return a full representation of the GroupRepresentation objects
     */
    @Path("{role-name}/groups")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<GroupRepresentation> getGroupsInRole(final @PathParam("role-name") String roleName,
                                                     @QueryParam("first") Integer firstResult,
                                                     @QueryParam("max") Integer maxResults,
                                                     @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {

        auth.roles().requireView(roleContainer);
        firstResult = firstResult != null ? firstResult : 0;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;

        RoleModel role = roleContainer.getRole(roleName);

        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        List<GroupModel> groupsModel = realmProvider.getGroupsByRole(realm, role, firstResult, maxResults);

        return groupsModel.stream()
                .map(g -> ModelToRepresentation.toRepresentation(g, !briefRepresentation))
                .collect(Collectors.toList());
    }
}
