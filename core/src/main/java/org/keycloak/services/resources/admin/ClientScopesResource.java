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
package org.keycloak.services.resources.admin;

import org.jboss.resteasy.annotations.cache.NoCache;
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
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

/**
 * Base resource class for managing a realm's client scopes.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Client Scopes
 */
public class ClientScopesResource {
    protected static final Logger LOG = LoggerFactory.getLogger(ClientScopesResource.class);
    protected RealmModel realm;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public ClientScopesResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
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
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
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
     *
     * @param rep
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
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
    @Path("{id}")
    @NoCache
    public ClientScopeResource getClientScope(final @PathParam("id") String id) {
        auth.clients().requireListClientScopes();
        ClientScopeModel clientModel = realm.getClientScopeById(id);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client scope");
        }
        ClientScopeResource clientResource = new ClientScopeResource(realm, auth, clientModel, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(clientResource);
        return clientResource;
    }

}
