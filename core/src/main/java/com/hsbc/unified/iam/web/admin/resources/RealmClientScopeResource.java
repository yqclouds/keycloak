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
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.services.ErrorResponse;
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
public class RealmClientScopeResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientScopeResource.class);
    protected RealmModel realm;
    protected ClientScopeModel clientScope;

    public RealmClientScopeResource(RealmModel realm, ClientScopeModel clientScope) {
        this.realm = realm;
        this.clientScope = clientScope;
    }

    @Path("protocol-mappers")
    public RealmProtocolMappersResource getProtocolMappers() {
        RealmProtocolMappersResource mappers = new RealmProtocolMappersResource(realm, clientScope);
        ResteasyProviderFactory.getInstance().injectProperties(mappers);
        return mappers;
    }

    /**
     * Base path for managing the role scope mappings for the client scope
     */
    @Path("scope-mappings")
    public RealmScopeMappedResource getScopeMappedResource() {
        return new RealmScopeMappedResource(realm, clientScope);
    }

    /**
     * Update the client scope
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response update(final ClientScopeRepresentation rep) {
        try {
            RepresentationToModel.updateClientScope(rep, clientScope);
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
        return modelToRepresentation.toRepresentation(clientScope);
    }

    /**
     * Delete the client scope
     */
    @DELETE
    @NoCache
    public Response deleteClientScope() {
        try {
            realm.removeClientScope(clientScope.getId());
            return Response.noContent().build();
        } catch (ModelException me) {
            return ErrorResponse.error(me.getMessage(), Response.Status.BAD_REQUEST);
        }
    }
}
