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

package org.keycloak.services.clientregistration;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultClientRegistrationProvider extends AbstractClientRegistrationProvider {
    @Autowired
    private KeycloakContext keycloakContext;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createDefault(ClientRepresentation client) {
        DefaultClientRegistrationContext context = new DefaultClientRegistrationContext(client, this);
        client = create(context);
        URI uri = keycloakContext.getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
        return Response.created(uri).entity(client).build();
    }

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDefault(@PathParam("clientId") String clientId) {
        ClientModel client = keycloakContext.getRealm().getClientByClientId(clientId);
        ClientRepresentation clientRepresentation = get(client);
        return Response.ok(clientRepresentation).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateDefault(@PathParam("clientId") String clientId, ClientRepresentation client) {
        DefaultClientRegistrationContext context = new DefaultClientRegistrationContext(client, this);
        client = update(clientId, context);
        return Response.ok(client).build();
    }

    @DELETE
    @Path("{clientId}")
    public void deleteDefault(@PathParam("clientId") String clientId) {
        delete(clientId);
    }
}
