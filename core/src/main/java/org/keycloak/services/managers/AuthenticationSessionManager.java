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

package org.keycloak.services.managers;

import com.hsbc.unified.iam.core.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.protocol.RestartLoginCookie;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.sessions.StickySessionEncoderProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.UriInfo;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticationSessionManager {

    public static final String AUTH_SESSION_ID = "AUTH_SESSION_ID";

    public static final int AUTH_SESSION_LIMIT = 3;

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationSessionManager.class);

    @Autowired
    private AuthenticationSessionProvider authenticationSessionProvider;
    @Autowired
    private UserSessionProvider userSessionProvider;

    /**
     * Creates a fresh authentication session for the given realm . Optionally sets the browser
     * authentication session cookie {@link #AUTH_SESSION_ID} with the ID of the new session.
     *
     * @param realm
     * @param browserCookie Set the cookie in the browser for the
     * @return
     */
    public RootAuthenticationSessionModel createAuthenticationSession(RealmModel realm, boolean browserCookie) {
        RootAuthenticationSessionModel rootAuthSession = authenticationSessionProvider.createRootAuthenticationSession(realm);

        if (browserCookie) {
            setAuthSessionCookie(rootAuthSession.getId(), realm);
        }

        return rootAuthSession;
    }


    public RootAuthenticationSessionModel getCurrentRootAuthenticationSession(RealmModel realm) {
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            RootAuthenticationSessionModel rootAuthSession = authenticationSessionProvider.getRootAuthenticationSession(realm, sessionId);

            if (rootAuthSession != null) {
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return rootAuthSession;
            }

            return null;
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }


    public UserSessionModel getUserSessionFromAuthCookie(RealmModel realm) {
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            UserSessionModel userSession = userSessionProvider.getUserSession(realm, sessionId);

            if (userSession != null) {
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return userSession;
            }

            return null;
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }


    /**
     * Returns current authentication session if it exists, otherwise returns {@code null}.
     *
     * @param realm
     * @return
     */
    public AuthenticationSessionModel getCurrentAuthenticationSession(RealmModel realm, ClientModel client, String tabId) {
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            AuthenticationSessionModel authSession = getAuthenticationSessionByIdAndClient(realm, sessionId, client, tabId);

            if (authSession != null) {
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return authSession;
            }

            return null;
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }

    @Autowired
    private StickySessionEncoderProvider stickySessionEncoderProvider;
    @Autowired
    private KeycloakContext context;

    /**
     * @param authSessionId decoded authSessionId (without route info attached)
     * @param realm
     */
    public void setAuthSessionCookie(String authSessionId, RealmModel realm) {
        UriInfo uriInfo = context.getUri();
        String cookiePath = AuthenticationManager.getRealmCookiePath(realm, uriInfo);

        boolean sslRequired = realm.getSslRequired().isRequired(context.getConnection());

        String encodedAuthSessionId = stickySessionEncoderProvider.encodeSessionId(authSessionId);

        CookieHelper.addCookie(AUTH_SESSION_ID, encodedAuthSessionId, cookiePath, null, null, -1, sslRequired, true);

        LOG.debug("Set AUTH_SESSION_ID cookie with value {}", encodedAuthSessionId);
    }


    /**
     * @param encodedAuthSessionId encoded ID with attached route in cluster environment (EG. "5e161e00-d426-4ea6-98e9-52eb9844e2d7.node1" )
     * @return object with decoded and actually encoded authSessionId
     */
    AuthSessionId decodeAuthSessionId(String encodedAuthSessionId) {
        LOG.debug("Found AUTH_SESSION_ID cookie with value {}", encodedAuthSessionId);
        String decodedAuthSessionId = stickySessionEncoderProvider.decodeSessionId(encodedAuthSessionId);
        String reencoded = stickySessionEncoderProvider.encodeSessionId(decodedAuthSessionId);

        return new AuthSessionId(decodedAuthSessionId, reencoded);
    }


    void reencodeAuthSessionCookie(String oldEncodedAuthSessionId, AuthSessionId newAuthSessionId, RealmModel realm) {
        if (!oldEncodedAuthSessionId.equals(newAuthSessionId.getEncodedId())) {
            LOG.debug("Route changed. Will update authentication session cookie. Old: '{}', New: '{}'", oldEncodedAuthSessionId,
                    newAuthSessionId.getEncodedId());
            setAuthSessionCookie(newAuthSessionId.getDecodedId(), realm);
        }
    }


    /**
     * @param realm
     * @return list of the values of AUTH_SESSION_ID cookies. It is assumed that values could be encoded with route added (EG. "5e161e00-d426-4ea6-98e9-52eb9844e2d7.node1" )
     */
    List<String> getAuthSessionCookies(RealmModel realm) {
        Set<String> cookiesVal = CookieHelper.getCookieValue(AUTH_SESSION_ID);

        if (cookiesVal.size() > 1) {
            AuthenticationManager.expireOldAuthSessionCookie(realm, context.getUri(), context.getConnection());
        }

        List<String> authSessionIds = cookiesVal.stream().limit(AUTH_SESSION_LIMIT).collect(Collectors.toList());

        if (authSessionIds.isEmpty()) {
            LOG.debug("Not found AUTH_SESSION_ID cookie");
        }

        return authSessionIds;
    }


    public void removeAuthenticationSession(RealmModel realm, AuthenticationSessionModel authSession, boolean expireRestartCookie) {
        RootAuthenticationSessionModel rootAuthSession = authSession.getParentSession();

        LOG.debug("Removing authSession '{}'. Expire restart cookie: %b", rootAuthSession.getId(), expireRestartCookie);
        authenticationSessionProvider.removeRootAuthenticationSession(realm, rootAuthSession);

        // expire restart cookie
        if (expireRestartCookie) {
            ClientConnection clientConnection = context.getConnection();
            UriInfo uriInfo = context.getUri();
            RestartLoginCookie.expireRestartCookie(realm, clientConnection, uriInfo);
        }
    }


    // Check to see if we already have authenticationSession with same ID
    public UserSessionModel getUserSession(AuthenticationSessionModel authSession) {
        return userSessionProvider.getUserSession(authSession.getRealm(), authSession.getParentSession().getId());
    }


    // Don't look at cookie. Just lookup authentication session based on the ID and client. Return null if not found
    public AuthenticationSessionModel getAuthenticationSessionByIdAndClient(RealmModel realm, String authSessionId, ClientModel client, String tabId) {
        RootAuthenticationSessionModel rootAuthSession = authenticationSessionProvider.getRootAuthenticationSession(realm, authSessionId);
        return rootAuthSession == null ? null : rootAuthSession.getAuthenticationSession(client, tabId);
    }
}
