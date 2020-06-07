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
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.user.SynchronizationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/user-storage",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmUserStorageProviderResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmUserStorageProviderResource.class);

    protected RealmModel realm;

    @Context
    protected ClientConnection clientConnection;

    @Autowired
    private KeycloakContext keycloakContext;

    @Context
    protected HttpHeaders headers;

    public RealmUserStorageProviderResource(RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Need this for admin console to display simple name of provider when displaying user detail
     * <p>
     * KEYCLOAK-4328
     */
    @GET
    @Path("{id}/name")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> getSimpleName(@PathParam("id") String id) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        if (!model.getProviderType().equals(UserStorageProvider.class.getName())) {
            throw new NotFoundException("found, but not a UserStorageProvider");
        }

        Map<String, String> data = new HashMap<>();
        data.put("id", model.getId());
        data.put("name", model.getName());
        return data;
    }


    /**
     * Trigger sync of users
     * <p>
     * Action can be "triggerFullSync" or "triggerChangedUsersSync"
     */
    @POST
    @Path("{id}/sync")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public SynchronizationResult syncUsers(@PathParam("id") String id,
                                           @QueryParam("action") String action) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        if (!model.getProviderType().equals(UserStorageProvider.class.getName())) {
            throw new NotFoundException("found, but not a UserStorageProvider");
        }

        LOG.debug("Syncing users");

        if (action == null || action.equals("")) {
            LOG.debug("Missing action");
            throw new BadRequestException("Missing action");
        } else {
            LOG.debug("Unknown action: " + action);
            throw new BadRequestException("Unknown action: " + action);
        }
    }

    /**
     * Remove imported users
     */
    @POST
    @Path("{id}/remove-imported-users")
    @NoCache
    public void removeImportedUsers(@PathParam("id") String id) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        if (!model.getProviderType().equals(UserStorageProvider.class.getName())) {
            throw new NotFoundException("found, but not a UserStorageProvider");
        }

        userProvider.removeImportedUsers(realm, id);
    }

    /**
     * Unlink imported users from a storage provider
     */
    @POST
    @Path("{id}/unlink-users")
    @NoCache
    public void unlinkUsers(@PathParam("id") String id) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        if (!model.getProviderType().equals(UserStorageProvider.class.getName())) {
            throw new NotFoundException("found, but not a UserStorageProvider");
        }

        userProvider.unlinkUsers(realm, id);
    }

    @Autowired
    private UserProvider userProvider;

    @Autowired
    private Map<ComponentModel, LDAPStorageMapper> ldapStorageMappers;

    /**
     * Trigger sync of mapper data related to ldap mapper (roles, groups, ...)
     * <p>
     * direction is "fedToKeycloak" or "keycloakToFed"
     */
    @POST
    @Path("{parentId}/mappers/{id}/sync")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public SynchronizationResult syncMapperData(@PathParam("parentId") String parentId, @PathParam("id") String mapperId, @QueryParam("direction") String direction) {
        ComponentModel parentModel = realm.getComponent(parentId);
        if (parentModel == null) throw new NotFoundException("Parent model not found");
        ComponentModel mapperModel = realm.getComponent(mapperId);
        if (mapperModel == null) throw new NotFoundException("Mapper model not found");

        LDAPStorageMapper mapper = ldapStorageMappers.get(mapperModel);

        SynchronizationResult syncResult;
        if ("fedToKeycloak".equals(direction)) {
            syncResult = mapper.syncDataFromFederationProviderToKeycloak(realm);
        } else if ("keycloakToFed".equals(direction)) {
            syncResult = mapper.syncDataFromKeycloakToFederationProvider(realm);
        } else {
            throw new BadRequestException("Unknown direction: " + direction);
        }

        Map<String, Object> eventRep = new HashMap<>();
        eventRep.put("action", direction);
        eventRep.put("result", syncResult);
        return syncResult;
    }
}
