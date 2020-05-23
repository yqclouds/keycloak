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
import org.keycloak.models.*;
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


/**
 * Base resource class for managing one particular client of a realm.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Client Scopes
 */
public class ClientScopeResource {
    protected static final Logger LOG = LoggerFactory.getLogger(ClientScopeResource.class);
    protected RealmModel realm;
    protected ClientScopeModel clientScope;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public ClientScopeResource(RealmModel realm, AdminPermissionEvaluator auth, ClientScopeModel clientScope, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.auth = auth;
        this.clientScope = clientScope;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT_SCOPE);
    }

    @Path("protocol-mappers")
    public ProtocolMappersResource getProtocolMappers() {
        AdminPermissionEvaluator.RequirePermissionCheck manageCheck = () -> auth.clients().requireManage(clientScope);
        AdminPermissionEvaluator.RequirePermissionCheck viewCheck = () -> auth.clients().requireView(clientScope);
        ProtocolMappersResource mappers = new ProtocolMappersResource(realm, clientScope, auth, adminEvent, manageCheck, viewCheck);
        ResteasyProviderFactory.getInstance().injectProperties(mappers);
        return mappers;
    }

    /**
     * Base path for managing the role scope mappings for the client scope
     */
    @Path("scope-mappings")
    public ScopeMappedResource getScopeMappedResource() {
        AdminPermissionEvaluator.RequirePermissionCheck manageCheck = () -> auth.clients().requireManage(clientScope);
        AdminPermissionEvaluator.RequirePermissionCheck viewCheck = () -> auth.clients().requireView(clientScope);
        return new ScopeMappedResource(realm, auth, clientScope, adminEvent, manageCheck, viewCheck);
    }

    @Autowired
    private KeycloakContext keycloakContext;

    /**
     * Update the client scope
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response update(final ClientScopeRepresentation rep) {
        auth.clients().requireManageClientScopes();

        try {
            RepresentationToModel.updateClientScope(rep, clientScope);
            adminEvent.operation(OperationType.UPDATE).resourcePath(keycloakContext.getUri()).representation(rep).success();
            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Client ScopeModel " + rep.getName() + " already exists");
        }
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;


    /**
     * Get representation of the client scope
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public ClientScopeRepresentation getClientScope() {
        auth.clients().requireView(clientScope);


        return modelToRepresentation.toRepresentation(clientScope);
    }

    /**
     * Delete the client scope
     */
    @DELETE
    @NoCache
    public Response deleteClientScope() {
        auth.clients().requireManage(clientScope);

        try {
            realm.removeClientScope(clientScope.getId());
            adminEvent.operation(OperationType.DELETE).resourcePath(keycloakContext.getUri()).success();
            return Response.noContent().build();
        } catch (ModelException me) {
            return ErrorResponse.error(me.getMessage(), Response.Status.BAD_REQUEST);
        }
    }


}
