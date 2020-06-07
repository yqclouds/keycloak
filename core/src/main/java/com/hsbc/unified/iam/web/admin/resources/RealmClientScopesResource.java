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
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.services.ErrorResponse;
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

    public RealmClientScopesResource(RealmModel realm) {
        this.realm = realm;
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
        List<ClientScopeRepresentation> rep = new ArrayList<>();
        List<ClientScopeModel> clientModels = realm.getClientScopes();

        for (ClientScopeModel clientModel : clientModels) {
            rep.add(modelToRepresentation.toRepresentation(clientModel));
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
        try {
            ClientScopeModel clientModel = representationToModel.createClientScope(realm, rep);

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
        ClientScopeModel clientModel = realm.getClientScopeById(id);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client scope");
        }
        RealmClientScopeResource clientResource = new RealmClientScopeResource(realm, clientModel);
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
        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new NotFoundException("Client scope not found");
        }
        realm.addDefaultClientScope(clientScope, defaultScope);
    }

    @RequestMapping(value = "/default-default-client-scopes/{clientScopeId}", method = RequestMethod.DELETE)
    public void removeDefaultDefaultClientScope(@PathParam("clientScopeId") String clientScopeId) {
        ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
        if (clientScope == null) {
            throw new NotFoundException("Client scope not found");
        }
        realm.removeDefaultClientScope(clientScope);
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
