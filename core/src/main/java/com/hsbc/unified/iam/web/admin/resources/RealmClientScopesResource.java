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

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Base resource class for managing a realm's client scopes.
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmClientScopesResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientScopesResource.class);
    protected RealmModel realm;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public RealmClientScopesResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT_SCOPE);
    }

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private ModelToRepresentation modelToRepresentation;

    @Autowired
    private RepresentationToModel representationToModel;

    /**
     * Get client scopes belonging to the realm
     * <p>
     * Returns a list of client scopes belonging to the realm
     */
    @RequestMapping(value = "/client-scopes", method = RequestMethod.GET)
    public List<ClientScopeRepresentation> getClientScopes() {
        auth.clients().requireListClientScopes();

        List<ClientScopeRepresentation> rep = new ArrayList<>();
        List<ClientScopeModel> clientModels = realm.getClientScopes();

        boolean viewable = auth.clients().canViewClientScopes();
        for (ClientScopeModel clientModel : clientModels) {
            if (viewable) rep.add(modelToRepresentation.toRepresentation(clientModel));
            else {
                ClientScopeRepresentation tempRep = new ClientScopeRepresentation();
                tempRep.setName(clientModel.getName());
                tempRep.setId(clientModel.getId());
                tempRep.setProtocol(clientModel.getProtocol());
            }
        }
        return rep;
    }

    /**
     * Create a new client scope
     * <p>
     * Client ScopeModel's name must be unique!
     */
    @RequestMapping(value = "/client-scopes", method = RequestMethod.POST)
    public Response createClientScope(ClientScopeRepresentation rep) {
        auth.clients().requireManageClientScopes();

        try {
            ClientScopeModel clientModel = representationToModel.createClientScope(realm, rep);

            adminEvent.operation(OperationType.CREATE).resourcePath(keycloakContext.getUri(), clientModel.getId()).representation(rep).success();

            return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(clientModel.getId()).build()).build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Client ScopeModel " + rep.getName() + " already exists");
        }
    }

    /**
     * Base path for managing a specific client scope.
     */
    @RequestMapping(value = "/client-scopes/{id}", method = RequestMethod.GET)
    public RealmClientScopeResource getClientScope(final @PathParam("id") String id) {
        auth.clients().requireListClientScopes();
        ClientScopeModel clientModel = realm.getClientScopeById(id);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client scope");
        }
        RealmClientScopeResource clientResource = new RealmClientScopeResource(realm, auth, clientModel, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(clientResource);
        return clientResource;
    }

    /**
     * Get realm default client scopes.  Only name and ids are returned.
     */
    @RequestMapping(value = "/default-default-client-scopes", method = RequestMethod.GET)
    public List<ClientScopeRepresentation> getDefaultDefaultClientScopes() {
        return getDefaultClientScopes(true);
    }

    private List<ClientScopeRepresentation> getDefaultClientScopes(boolean defaultScope) {
        auth.clients().requireViewClientScopes();

        List<ClientScopeRepresentation> defaults = new LinkedList<>();
        for (ClientScopeModel clientScope : realm.getDefaultClientScopes(defaultScope)) {
            ClientScopeRepresentation rep = new ClientScopeRepresentation();
            rep.setId(clientScope.getId());
            rep.setName(clientScope.getName());
            defaults.add(rep);
        }
        return defaults;
    }

    @RequestMapping(value = "/default-default-client-scopes/{clientScopeId}", method = RequestMethod.PUT)
    public void addDefaultDefaultClientScope(@PathParam("clientScopeId") String clientScopeId) {
        addDefaultClientScope(clientScopeId, true);
    }

    private void addDefaultClientScope(String clientScopeId, boolean defaultScope) {
        auth.clients().requireManageClientScopes();

        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new NotFoundException("Client scope not found");
        }
        realm.addDefaultClientScope(clientScope, defaultScope);

        adminEvent.operation(OperationType.CREATE).resource(ResourceType.CLIENT_SCOPE).resourcePath(keycloakContext.getUri()).success();
    }

    @RequestMapping(value = "/default-default-client-scopes/{clientScopeId}", method = RequestMethod.DELETE)
    public void removeDefaultDefaultClientScope(@PathParam("clientScopeId") String clientScopeId) {
        auth.clients().requireManageClientScopes();

        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new NotFoundException("Client scope not found");
        }
        realm.removeDefaultClientScope(clientScope);

        adminEvent.operation(OperationType.DELETE).resource(ResourceType.CLIENT_SCOPE)
                .resourcePath(keycloakContext.getUri()).success();
    }

    /**
     * Get realm optional client scopes.  Only name and ids are returned.
     */
    @RequestMapping(value = "/default-optional-client-scopes", method = RequestMethod.GET)
    public List<ClientScopeRepresentation> getDefaultOptionalClientScopes() {
        return getDefaultClientScopes(false);
    }

    @RequestMapping(value = "/default-optional-client-scopes/{clientScopeId}", method = RequestMethod.PUT)
    public void addDefaultOptionalClientScope(@PathParam("clientScopeId") String clientScopeId) {
        addDefaultClientScope(clientScopeId, false);
    }

    @RequestMapping(value = "/default-optional-client-scopes/{clientScopeId}", method = RequestMethod.DELETE)
    public void removeDefaultOptionalClientScope(@PathParam("clientScopeId") String clientScopeId) {
        removeDefaultDefaultClientScope(clientScopeId);
    }
}
