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

import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

/**
 * Base path for managing client initial access tokens
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/clients-initial-access",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmClientInitialAccessResource {

    private final AdminPermissionEvaluator auth;
    private final RealmModel realm;
    private final AdminEventBuilder adminEvent;

    @Context
    protected KeycloakContext keycloakContext;
    @Autowired
    private UserSessionProvider userSessionProvider;
    @Autowired
    private UserProvider userProvider;
    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private ClientRegistrationTokenUtils clientRegistrationTokenUtils;

    public RealmClientInitialAccessResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.auth = auth;
        this.realm = realm;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT_INITIAL_ACCESS_MODEL);

    }

    /**
     * Create a new initial access token.
     *
     * @param config
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public ClientInitialAccessPresentation create(ClientInitialAccessCreatePresentation config, @Context final HttpServletResponse response) {
        auth.clients().requireManage();

        int expiration = config.getExpiration() != null ? config.getExpiration() : 0;
        int count = config.getCount() != null ? config.getCount() : 1;

        ClientInitialAccessModel clientInitialAccessModel = realmProvider.createClientInitialAccessModel(realm, expiration, count);

        adminEvent.operation(OperationType.CREATE).resourcePath(keycloakContext.getUri(), clientInitialAccessModel.getId()).representation(config).success();

        ClientInitialAccessPresentation rep = wrap(clientInitialAccessModel);

        String token = clientRegistrationTokenUtils.createInitialAccessToken(realm, clientInitialAccessModel);
        rep.setToken(token);

        response.setStatus(Response.Status.CREATED.getStatusCode());
        response.setHeader(HttpHeaders.LOCATION, keycloakContext.getUri().getAbsolutePathBuilder().path(clientInitialAccessModel.getId()).build().toString());

        return rep;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<ClientInitialAccessPresentation> list() {
        auth.clients().requireView();

        List<ClientInitialAccessModel> models = realmProvider.listClientInitialAccess(realm);
        List<ClientInitialAccessPresentation> reps = new LinkedList<>();
        for (ClientInitialAccessModel m : models) {
            ClientInitialAccessPresentation r = wrap(m);
            reps.add(r);
        }
        return reps;
    }

    @DELETE
    @Path("{id}")
    public void delete(final @PathParam("id") String id) {
        auth.clients().requireManage();

        realmProvider.removeClientInitialAccessModel(realm, id);
        adminEvent.operation(OperationType.DELETE).resourcePath(keycloakContext.getUri()).success();
    }

    private ClientInitialAccessPresentation wrap(ClientInitialAccessModel model) {
        ClientInitialAccessPresentation rep = new ClientInitialAccessPresentation();
        rep.setId(model.getId());
        rep.setTimestamp(model.getTimestamp());
        rep.setExpiration(model.getExpiration());
        rep.setCount(model.getCount());
        rep.setRemainingCount(model.getRemainingCount());
        return rep;
    }

}
