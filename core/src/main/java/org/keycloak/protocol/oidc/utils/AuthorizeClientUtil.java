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

package org.keycloak.protocol.oidc.utils;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorResponseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthorizeClientUtil {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizeClientUtil.class);

    public ClientAuthResult authorizeClient(EventBuilder event) {
        AuthenticationProcessor processor = getAuthenticationProcessor(event);

        Response response = processor.authenticateClient();
        if (response != null) {
            throw new WebApplicationException(response);
        }

        ClientModel client = processor.getClient();
        if (client == null) {
            throw new ErrorResponseException(Errors.INVALID_CLIENT, "Client authentication ended, but client is null", Response.Status.BAD_REQUEST);
        }

        String protocol = client.getProtocol();
        if (protocol == null) {
            LOG.warn("Client '{}' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration", client.getClientId());
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }

        if (!protocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorResponseException(Errors.INVALID_CLIENT, "Wrong client protocol.", Response.Status.BAD_REQUEST);
        }

        keycloakContext.setClient(client);

        return new ClientAuthResult(client, processor.getClientAuthAttributes());
    }

    @Autowired
    private KeycloakContext keycloakContext;

    public AuthenticationProcessor getAuthenticationProcessor(EventBuilder event) {
        RealmModel realm = keycloakContext.getRealm();

        AuthenticationFlowModel clientAuthFlow = realm.getClientAuthenticationFlow();
        String flowId = clientAuthFlow.getId();

        AuthenticationProcessor processor = new AuthenticationProcessor();
        processor.setFlowId(flowId)
                .setConnection(keycloakContext.getConnection())
                .setEventBuilder(event)
                .setRealm(realm)
                .setUriInfo(keycloakContext.getUri())
                .setRequest(keycloakContext.getContextObject(HttpRequest.class));

        return processor;
    }

    @Autowired
    private Map<String, ClientAuthenticatorFactory> clientAuthenticatorFactories;

    public ClientAuthenticatorFactory findClientAuthenticatorForOIDCAuthMethod(String oidcAuthMethod) {
        for (ClientAuthenticatorFactory clientAuthFactory : clientAuthenticatorFactories.values()) {
            if (clientAuthFactory.getProtocolAuthenticatorMethods(OIDCLoginProtocol.LOGIN_PROTOCOL).contains(oidcAuthMethod)) {
                return clientAuthFactory;
            }
        }

        return null;
    }

    public static class ClientAuthResult {

        private final ClientModel client;
        private final Map<String, String> clientAuthAttributes;

        private ClientAuthResult(ClientModel client, Map<String, String> clientAuthAttributes) {
            this.client = client;
            this.clientAuthAttributes = clientAuthAttributes;
        }

        public ClientModel getClient() {
            return client;
        }

        public Map<String, String> getClientAuthAttributes() {
            return clientAuthAttributes;
        }
    }

}
