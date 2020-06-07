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
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * @author Bill Burke
 * @resource Groups
 */
public class RealmGroupResource {

    private final RealmModel realm;
    private final GroupModel group;

    public RealmGroupResource(RealmModel realm, GroupModel group) {
        this.realm = realm;
        this.group = group;
    }

    public static void updateGroup(GroupRepresentation rep, GroupModel model) {
        if (rep.getName() != null) model.setName(rep.getName());

        if (rep.getAttributes() != null) {
            Set<String> attrsToRemove = new HashSet<>(model.getAttributes().keySet());
            attrsToRemove.removeAll(rep.getAttributes().keySet());
            for (Map.Entry<String, List<String>> attr : rep.getAttributes().entrySet()) {
                model.setAttribute(attr.getKey(), attr.getValue());
            }

            for (String attr : attrsToRemove) {
                model.removeAttribute(attr);
            }
        }
    }

    public static ManagementPermissionReference toMgmtRef(GroupModel group, AdminPermissionManagement permissions) {
        ManagementPermissionReference ref = new ManagementPermissionReference();
        ref.setEnabled(true);
        ref.setResource(permissions.groups().resource(group).getId());
        ref.setScopePermissions(permissions.groups().getPermissions(group));
        return ref;
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public GroupRepresentation getGroup() {
        GroupRepresentation rep = ModelToRepresentation.toGroupHierarchy(group, true);

//        rep.setAccess(auth.groups().getAccess(group));

        return rep;
    }

    /**
     * Update group, ignores subgroups.
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateGroup(GroupRepresentation rep) {
        for (GroupModel sibling : siblings()) {
            if (Objects.equals(sibling.getId(), group.getId())) continue;
            if (sibling.getName().equals(rep.getName())) {
                return ErrorResponse.exists("Sibling group named '" + rep.getName() + "' already exists.");
            }
        }

        updateGroup(rep, group);

        return Response.noContent().build();
    }

    private List<GroupModel> siblings() {
        if (group.getParentId() == null) {
            return realm.getTopLevelGroups();
        } else {
            return new ArrayList<>(group.getParent().getSubGroups());
        }
    }

    @DELETE
    public void deleteGroup() {
        realm.removeGroup(group);
    }

    /**
     * Set or create child.  This will just set the parent if it exists.  Create it and set the parent
     * if the group doesn't exist.
     */
    @POST
    @Path("children")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addChild(GroupRepresentation rep) {
        for (GroupModel group : group.getSubGroups()) {
            if (group.getName().equals(rep.getName())) {
                return ErrorResponse.exists("Parent already contains subgroup named '" + rep.getName() + "'");
            }
        }

        Response.ResponseBuilder builder = Response.status(204);
        GroupModel child;
        if (rep.getId() != null) {
            child = realm.getGroupById(rep.getId());
            if (child == null) {
                throw new NotFoundException("Could not find child by id");
            }
        } else {
            child = realm.createGroup(rep.getName(), group);
            updateGroup(rep, child);
            rep.setId(child.getId());
        }

        GroupRepresentation childRep = ModelToRepresentation.toGroupHierarchy(child, true);
        return builder.type(MediaType.APPLICATION_JSON_TYPE).entity(childRep).build();
    }

    @Path("role-mappings")
    public RealmRoleMapperResource getRoleMappings() {
        RealmRoleMapperResource resource = new RealmRoleMapperResource(realm, group);
        ResteasyProviderFactory.getInstance().injectProperties(resource);
        return resource;
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;
    @Autowired
    private UserProvider userProvider;

    /**
     * Get users
     * <p>
     * Returns a list of users, filtered according to query parameters
     *
     * @param firstResult         Pagination offset
     * @param maxResults          Maximum results size (defaults to 100)
     * @param briefRepresentation Only return basic information (only guaranteed to return id, username, created, first and last name,
     *                            email, enabled state, email verification state, federation link, and access.
     *                            Note that it means that namely user attributes, required actions, and not before are not returned.)
     */
    @GET
    @NoCache
    @Path("members")
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserRepresentation> getMembers(@QueryParam("first") Integer firstResult,
                                               @QueryParam("max") Integer maxResults,
                                               @QueryParam("briefRepresentation") Boolean briefRepresentation) {
        firstResult = firstResult != null ? firstResult : 0;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;
        boolean briefRepresentationB = briefRepresentation != null && briefRepresentation;

        List<UserRepresentation> results = new ArrayList<>();
        List<UserModel> userModels = userProvider.getGroupMembers(realm, group, firstResult, maxResults);

        for (UserModel user : userModels) {
            UserRepresentation userRep = briefRepresentationB
                    ? ModelToRepresentation.toBriefRepresentation(user)
                    : modelToRepresentation.toRepresentation(realm, user);

            results.add(userRep);
        }
        return results;
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     */
    @Path("management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions() {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (!permissions.groups().isPermissionsEnabled(group)) {
            return new ManagementPermissionReference();
        }
        return toMgmtRef(group, permissions);
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     *
     * @return initialized manage permissions reference
     */
    @Path("management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(ManagementPermissionReference ref) {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.groups().setPermissionsEnabled(group, ref.isEnabled());
        if (ref.isEnabled()) {
            return toMgmtRef(group, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

}

