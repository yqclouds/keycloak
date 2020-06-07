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
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/groups",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmGroupsResource {

    private final RealmModel realm;
    @Autowired
    private KeycloakContext keycloakContext;
    private final AdminPermissionEvaluator auth;

    public RealmGroupsResource(RealmModel realm, AdminPermissionEvaluator auth) {
        this.realm = realm;
        this.auth = auth;
    }

    /**
     * Get group hierarchy.  Only name and ids are returned.
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<GroupRepresentation> getGroups(@QueryParam("search") String search,
                                               @QueryParam("first") Integer firstResult,
                                               @QueryParam("max") Integer maxResults,
                                               @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {
        auth.groups().requireList();

        List<GroupRepresentation> results;

        if (Objects.nonNull(search)) {
            results = ModelToRepresentation.searchForGroupByName(realm, !briefRepresentation, search.trim(), firstResult, maxResults);
        } else if (Objects.nonNull(firstResult) && Objects.nonNull(maxResults)) {
            results = ModelToRepresentation.toGroupHierarchy(realm, !briefRepresentation, firstResult, maxResults);
        } else {
            results = ModelToRepresentation.toGroupHierarchy(realm, !briefRepresentation);
        }

        return results;
    }

    /**
     * Does not expand hierarchy.  Subgroups will not be set.
     */
    @Path("{id}")
    public RealmGroupResource getGroupById(@PathParam("id") String id) {
        GroupModel group = realm.getGroupById(id);
        if (group == null) {
            throw new NotFoundException("Could not find group by id");
        }
        RealmGroupResource resource = new RealmGroupResource(realm, group, this.auth);
        ResteasyProviderFactory.getInstance().injectProperties(resource);
        return resource;
    }

    /**
     * Returns the groups counts.
     */
    @GET
    @NoCache
    @Path("count")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Long> getGroupCount(@QueryParam("search") String search,
                                           @QueryParam("top") @DefaultValue("false") boolean onlyTopGroups) {
        Long results;
        Map<String, Long> map = new HashMap<>();
        if (Objects.nonNull(search)) {
            results = realm.getGroupsCountByNameContaining(search);
        } else {
            results = realm.getGroupsCount(onlyTopGroups);
        }
        map.put("count", results);
        return map;
    }

    /**
     * create or add a top level realm groupSet or create child.  This will update the group and set the parent if it exists.  Create it and set the parent
     * if the group doesn't exist.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addTopLevelGroup(GroupRepresentation rep) {
        auth.groups().requireManage();

        GroupModel child;
        Response.ResponseBuilder builder = Response.status(204);
        try {
            if (rep.getId() != null) {
                child = realm.getGroupById(rep.getId());
                if (child == null) {
                    throw new NotFoundException("Could not find child by id");
                }
            } else {
                child = realm.createGroup(rep.getName());
                RealmGroupResource.updateGroup(rep, child);
                URI uri = keycloakContext.getUri().getAbsolutePathBuilder()
                        .path(child.getId()).build();
                builder.status(201).location(uri);

                rep.setId(child.getId());
            }
        } catch (ModelDuplicateException mde) {
            return ErrorResponse.exists("Top level group named '" + rep.getName() + "' already exists.");
        }

        return builder.build();
    }
}
