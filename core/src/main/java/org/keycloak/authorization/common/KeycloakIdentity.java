/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.apache.commons.lang.StringUtils;
import org.keycloak.authorization.attribute.Attributes;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response.Status;
import java.util.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakIdentity implements Identity {

    protected final AccessToken accessToken;
    protected final RealmModel realm;
    protected final Attributes attributes;
    private final boolean resourceServer;
    private final String id;

    @Autowired
    private UserProvider userProvider;
    @Autowired
    private UserSessionProvider userSessionProvider;

    public KeycloakIdentity(IDToken token, RealmModel realm) {
        if (token == null) {
            throw new ErrorResponseException("invalid_bearer_token", "Could not obtain bearer access_token from request.", Status.FORBIDDEN);
        }
        if (realm == null) {
            throw new ErrorResponseException("no_keycloak_session", "No realm set", Status.FORBIDDEN);
        }
        this.realm = realm;

        Map<String, Collection<String>> attributes = new HashMap<>();

        try {
            ObjectNode objectNode = JsonSerialization.createObjectNode(token);
            Iterator<String> iterator = objectNode.fieldNames();

            while (iterator.hasNext()) {
                String fieldName = iterator.next();
                JsonNode fieldValue = objectNode.get(fieldName);
                List<String> values = new ArrayList<>();

                if (fieldValue.isArray()) {
                    for (JsonNode jsonNode : fieldValue) {
                        values.add(jsonNode.asText());
                    }
                } else {
                    String value = fieldValue.asText();
                    if (StringUtils.isEmpty(value)) {
                        continue;
                    }

                    values.add(value);
                }

                if (!values.isEmpty()) {
                    attributes.put(fieldName, values);
                }
            }

            if (token instanceof AccessToken) {
                this.accessToken = (AccessToken) token;
            } else {
                UserSessionModel userSession = userSessionProvider.getUserSession(realm, token.getSessionState());
                if (userSession == null) {
                    userSession = userSessionProvider.getOfflineUserSession(realm, token.getSessionState());
                }

                ClientModel client = realm.getClientByClientId(token.getIssuedFor());
                AuthenticatedClientSessionModel clientSessionModel = userSession.getAuthenticatedClientSessions().get(client.getId());

                ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSessionModel);
                this.accessToken = new TokenManager().createClientAccessToken(realm, client, userSession.getUser(), userSession, clientSessionCtx);
            }

            AccessToken.Access realmAccess = this.accessToken.getRealmAccess();

            if (realmAccess != null) {
                attributes.put("kc.realm.roles", realmAccess.getRoles());
            }

            Map<String, AccessToken.Access> resourceAccess = this.accessToken.getResourceAccess();

            if (resourceAccess != null) {
                resourceAccess.forEach((clientId, access) -> attributes.put("kc.client." + clientId + ".roles", access.getRoles()));
            }

            ClientModel clientModel = getTargetClient();
            UserModel clientUser = null;

            if (clientModel != null) {
                clientUser = userProvider.getServiceAccount(clientModel);
            }

            UserModel userSession = getUserFromSessionState();

            this.resourceServer = clientUser != null && userSession.getId().equals(clientUser.getId());

            if (resourceServer) {
                this.id = clientModel.getId();
            } else {
                this.id = userSession.getId();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading attributes from security token.", e);
        }

        this.attributes = Attributes.from(attributes);
    }

    @Autowired
    private KeycloakContext keycloakContext;

    public KeycloakIdentity(AccessToken accessToken) {
        if (accessToken == null) {
            throw new ErrorResponseException("invalid_bearer_token", "Could not obtain bearer access_token from request.", Status.FORBIDDEN);
        }
        this.accessToken = accessToken;
        this.realm = keycloakContext.getRealm();

        Map<String, Collection<String>> attributes = new HashMap<>();

        try {
            ObjectNode objectNode = JsonSerialization.createObjectNode(this.accessToken);
            Iterator<String> iterator = objectNode.fieldNames();

            while (iterator.hasNext()) {
                String fieldName = iterator.next();
                JsonNode fieldValue = objectNode.get(fieldName);
                List<String> values = new ArrayList<>();

                if (fieldValue.isArray()) {
                    for (JsonNode jsonNode : fieldValue) {
                        values.add(jsonNode.asText());
                    }
                } else {
                    String value = fieldValue.asText();
                    if (StringUtils.isBlank(value)) {
                        continue;
                    }

                    values.add(value);
                }

                if (!values.isEmpty()) {
                    attributes.put(fieldName, values);
                }
            }

            AccessToken.Access realmAccess = accessToken.getRealmAccess();

            if (realmAccess != null) {
                attributes.put("kc.realm.roles", realmAccess.getRoles());
            }

            Map<String, AccessToken.Access> resourceAccess = accessToken.getResourceAccess();

            if (resourceAccess != null) {
                resourceAccess.forEach((clientId, access) -> attributes.put("kc.client." + clientId + ".roles", access.getRoles()));
            }

            ClientModel clientModel = getTargetClient();
            UserModel clientUser = null;

            if (clientModel != null) {
                clientUser = userProvider.getServiceAccount(clientModel);
            }

            UserModel userSession = getUserFromSessionState();

            this.resourceServer = clientUser != null && userSession.getId().equals(clientUser.getId());

            if (resourceServer) {
                this.id = clientModel.getId();
            } else {
                this.id = userSession.getId();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading attributes from security token.", e);
        }

        this.attributes = Attributes.from(attributes);
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public Attributes getAttributes() {
        return this.attributes;
    }

    public AccessToken getAccessToken() {
        return this.accessToken;
    }

    public boolean isResourceServer() {
        return this.resourceServer;
    }

    private ClientModel getTargetClient() {
        if (this.accessToken.getIssuedFor() != null) {
            return realm.getClientByClientId(accessToken.getIssuedFor());
        }

        if (this.accessToken.getAudience() != null && this.accessToken.getAudience().length > 0) {
            String audience = this.accessToken.getAudience()[0];
            return realm.getClientByClientId(audience);
        }

        return null;
    }

    private UserModel getUserFromSessionState() {
        UserSessionModel userSession = userSessionProvider.getUserSession(realm, accessToken.getSessionState());
        if (userSession == null) {
            userSession = userSessionProvider.getOfflineUserSession(realm, accessToken.getSessionState());
        }

        return userSession.getUser();
    }
}
