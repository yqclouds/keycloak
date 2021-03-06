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

import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.services.managers.ClientManager;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AdapterInstallationClientRegistrationProvider implements ClientRegistrationProvider {

    private EventBuilder event;
    private ClientRegistrationAuth auth;

    @Autowired
    private KeycloakContext keycloakContext;

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response get(@PathParam("clientId") String clientId) {
        event.event(EventType.CLIENT_INFO);

        ClientModel client = keycloakContext.getRealm().getClientByClientId(clientId);
        auth.requireView(client);

        ClientManager clientManager = new ClientManager(new RealmFacadeImpl());
        Object rep = clientManager.toInstallationRepresentation(keycloakContext.getRealm(), client, keycloakContext.getUri().getBaseUri());

        event.client(client.getClientId()).success();
        return Response.ok(rep).build();
    }

    @Override
    public ClientRegistrationAuth getAuth() {
        return auth;
    }

    @Override
    public void setAuth(ClientRegistrationAuth auth) {
        this.auth = auth;
    }

    @Override
    public EventBuilder getEvent() {
        return event;
    }

    @Override
    public void setEvent(EventBuilder event) {
        this.event = event;
    }

    @Override
    public void close() {
    }

}
