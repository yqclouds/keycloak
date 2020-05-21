/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Objects;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class UserSessionCrossDCManager {
    @Autowired
    private UserSessionProvider userSessionProvider;

    // get userSession if it has "authenticatedClientSession" of specified client attached to it. Otherwise download it from remoteCache
    public UserSessionModel getUserSessionWithClient(RealmModel realm, String id, boolean offline, String clientUUID) {
        return userSessionProvider.getUserSessionWithPredicate(realm, id, offline, userSession -> userSession.getAuthenticatedClientSessionByClient(clientUUID) != null);
    }


    // get userSession if it has "authenticatedClientSession" of specified client attached to it. Otherwise download it from remoteCache
    // TODO Probably remove this method once AuthenticatedClientSession.getAction is removed and information is moved to OAuth code JWT instead
    public UserSessionModel getUserSessionWithClient(RealmModel realm, String id, String clientUUID) {

        return userSessionProvider.getUserSessionWithPredicate(realm, id, false, (UserSessionModel userSession) -> {

            AuthenticatedClientSessionModel authSessions = userSession.getAuthenticatedClientSessionByClient(clientUUID);
            return authSessions != null;

        });
    }


    // Just check if userSession also exists on remoteCache. It can happen that logout happened on 2nd DC and userSession is already removed on remoteCache and this DC wasn't yet notified
    public UserSessionModel getUserSessionIfExistsRemotely(AuthenticationSessionManager asm, RealmModel realm) {
        List<String> sessionCookies = asm.getAuthSessionCookies(realm);

        return sessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = asm.decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            // This will remove userSession "locally" if it doesn't exists on remoteCache
            userSessionProvider.getUserSessionWithPredicate(realm, sessionId, false, (UserSessionModel userSession2) -> userSession2 == null);

            UserSessionModel userSession = userSessionProvider.getUserSession(realm, sessionId);

            if (userSession != null) {
                asm.reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return userSession;
            }

            return null;
        }).filter(Objects::nonNull).findFirst().orElse(null);
    }
}
