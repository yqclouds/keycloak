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

package org.keycloak.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hsbc.unified.iam.core.ClientConnection;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.TokenManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;

/**
 * This is an an encoded token that is stored as a cookie so that if there is a client timeout, then the authentication session
 * can be restarted.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RestartLoginCookie implements Token {
    public static final String KC_RESTART = "KC_RESTART";
    private static final Logger LOG = LoggerFactory.getLogger(RestartLoginCookie.class);
    @JsonProperty("cid")
    protected String clientId;

    @JsonProperty("pty")
    protected String authMethod;

    @JsonProperty("ruri")
    protected String redirectUri;

    @JsonProperty("act")
    protected String action;

    @JsonProperty("notes")
    protected Map<String, String> notes = new HashMap<>();

    @Deprecated // Backwards compatibility
    @JsonProperty("cs")
    protected String cs;

    public RestartLoginCookie() {
    }

    public RestartLoginCookie(AuthenticationSessionModel authSession) {
        this.action = authSession.getAction();
        this.clientId = authSession.getClient().getClientId();
        this.authMethod = authSession.getProtocol();
        this.redirectUri = authSession.getRedirectUri();
        for (Map.Entry<String, String> entry : authSession.getClientNotes().entrySet()) {
            notes.put(entry.getKey(), entry.getValue());
        }
    }

    public void setRestartCookie(RealmModel realm, ClientConnection connection, UriInfo uriInfo, AuthenticationSessionModel authSession) {
        RestartLoginCookie restart = new RestartLoginCookie(authSession);
        String encoded = tokenManager.encode(restart);
        String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        CookieHelper.addCookie(KC_RESTART, encoded, path, null, null, -1, secureOnly, true);
    }

    public static void expireRestartCookie(RealmModel realm, ClientConnection connection, UriInfo uriInfo) {
        String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        CookieHelper.addCookie(KC_RESTART, "", path, null, null, 0, secureOnly, true);
    }

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private TokenManager tokenManager;

    public AuthenticationSessionModel restartSession(RealmModel realm,
                                                     RootAuthenticationSessionModel rootSession, String expectedClientId) throws Exception {
        Cookie cook = keycloakContext.getRequestHeaders().getCookies().get(KC_RESTART);
        if (cook == null) {
            LOG.debug("KC_RESTART cookie doesn't exist");
            return null;
        }
        String encodedCookie = cook.getValue();

        RestartLoginCookie cookie = tokenManager.decode(encodedCookie, RestartLoginCookie.class);
        if (cookie == null) {
            LOG.debug("Failed to verify encoded RestartLoginCookie");
            return null;
        }

        ClientModel client = realm.getClientByClientId(cookie.getClientId());
        if (client == null) return null;

        // Restart just if client from cookie matches client from the URL.
        if (!client.getClientId().equals(expectedClientId)) {
            LOG.debug("Skip restarting from the KC_RESTART. Clients doesn't match: Cookie client: {}, Requested client: {}", client.getClientId(), expectedClientId);
            return null;
        }

        // Need to create brand new session and setup cookie
        if (rootSession == null) {
            rootSession = new AuthenticationSessionManager().createAuthenticationSession(realm, true);
        }

        AuthenticationSessionModel authSession = rootSession.createAuthenticationSession(client);
        authSession.setProtocol(cookie.getAuthMethod());
        authSession.setRedirectUri(cookie.getRedirectUri());
        authSession.setAction(cookie.getAction());
        for (Map.Entry<String, String> entry : cookie.getNotes().entrySet()) {
            authSession.setClientNote(entry.getKey(), entry.getValue());
        }

        return authSession;
    }

    public Map<String, String> getNotes() {
        return notes;
    }

    public void setNotes(Map<String, String> notes) {
        this.notes = notes;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.INTERNAL;
    }
}
