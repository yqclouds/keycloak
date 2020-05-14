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

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.models.*;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class UserSessionManager {

    private static final Logger LOG = LoggerFactory.getLogger(UserSessionManager.class);

    private final KeycloakSession kcSession;

    @Autowired
    private UserSessionPersisterProvider userSessionPersisterProvider;

    public UserSessionManager(KeycloakSession session) {
        this.kcSession = session;
    }

    public void createOrUpdateOfflineSession(AuthenticatedClientSessionModel clientSession, UserSessionModel userSession) {
        UserModel user = userSession.getUser();

        // Create and persist offline userSession if we don't have one
        UserSessionModel offlineUserSession = kcSession.sessions().getOfflineUserSession(clientSession.getRealm(), userSession.getId());
        if (offlineUserSession == null) {
            offlineUserSession = createOfflineUserSession(user, userSession);
        } else {
            // update lastSessionRefresh but don't need to persist
            offlineUserSession.setLastSessionRefresh(Time.currentTime());
        }

        // Create and persist clientSession
        AuthenticatedClientSessionModel offlineClientSession = offlineUserSession.getAuthenticatedClientSessionByClient(clientSession.getClient().getId());
        if (offlineClientSession == null) {
            createOfflineClientSession(user, clientSession, offlineUserSession);
        }
    }


    public UserSessionModel findOfflineUserSession(RealmModel realm, String userSessionId) {
        return kcSession.sessions().getOfflineUserSession(realm, userSessionId);
    }

    public Set<ClientModel> findClientsWithOfflineToken(RealmModel realm, UserModel user) {
        List<UserSessionModel> userSessions = kcSession.sessions().getOfflineUserSessions(realm, user);
        Set<ClientModel> clients = new HashSet<>();
        for (UserSessionModel userSession : userSessions) {
            Set<String> clientIds = userSession.getAuthenticatedClientSessions().keySet();
            for (String clientUUID : clientIds) {
                ClientModel client = realm.getClientById(clientUUID);
                clients.add(client);
            }
        }
        return clients;
    }

    public List<UserSessionModel> findOfflineSessions(RealmModel realm, UserModel user) {
        return kcSession.sessions().getOfflineUserSessions(realm, user);
    }

    public boolean revokeOfflineToken(UserModel user, ClientModel client) {
        RealmModel realm = client.getRealm();

        List<UserSessionModel> userSessions = kcSession.sessions().getOfflineUserSessions(realm, user);
        boolean anyRemoved = false;
        for (UserSessionModel userSession : userSessions) {
            AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
            if (clientSession != null) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Removing existing offline token for user '{}' and client '{}' .",
                            user.getUsername(), client.getClientId());
                }

                clientSession.detachFromUserSession();
                userSessionPersisterProvider.removeClientSession(userSession.getId(), client.getId(), true);
                checkOfflineUserSessionHasClientSessions(realm, user, userSession);
                anyRemoved = true;
            }
        }

        return anyRemoved;
    }

    public void revokeOfflineUserSession(UserSessionModel userSession) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Removing offline user session '{}' for user '{}' ", userSession.getId(), userSession.getLoginUsername());
        }
        kcSession.sessions().removeOfflineUserSession(userSession.getRealm(), userSession);
        userSessionPersisterProvider.removeUserSession(userSession.getId(), true);
    }

    public boolean isOfflineTokenAllowed(ClientSessionContext clientSessionCtx) {
        RoleModel offlineAccessRole = clientSessionCtx.getClientSession().getRealm().getRole(Constants.OFFLINE_ACCESS_ROLE);
        if (offlineAccessRole == null) {
//            ServicesLogger.LOGGER.roleNotInRealm(Constants.OFFLINE_ACCESS_ROLE);
            return false;
        }

        // Check if offline_access is allowed here. Even through composite roles
        return clientSessionCtx.getRoles().contains(offlineAccessRole);
    }

    private UserSessionModel createOfflineUserSession(UserModel user, UserSessionModel userSession) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Creating new offline user session. UserSessionID: '{}' , Username: '{}'", userSession.getId(), user.getUsername());
        }

        UserSessionModel offlineUserSession = kcSession.sessions().createOfflineUserSession(userSession);
        userSessionPersisterProvider.createUserSession(offlineUserSession, true);
        return offlineUserSession;
    }

    private void createOfflineClientSession(UserModel user, AuthenticatedClientSessionModel clientSession, UserSessionModel offlineUserSession) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Creating new offline token client session. ClientSessionId: '{}', UserSessionID: '{}' , Username: '{}', Client: '{}'",
                    clientSession.getId(), offlineUserSession.getId(), user.getUsername(), clientSession.getClient().getClientId());
        }

        kcSession.sessions().createOfflineClientSession(clientSession, offlineUserSession);
        userSessionPersisterProvider.createClientSession(clientSession, true);
    }

    // Check if userSession has any offline clientSessions attached to it. Remove userSession if not
    private void checkOfflineUserSessionHasClientSessions(RealmModel realm, UserModel user, UserSessionModel userSession) {
        // TODO: Might need optimization to prevent loading client sessions from cache
        if (!userSession.getAuthenticatedClientSessions().isEmpty()) {
            return;
        }

        if (LOG.isTraceEnabled()) {
            LOG.trace("Removing offline userSession for user {} as it doesn't have any client sessions attached. UserSessionID: {}", user.getUsername(), userSession.getId());
        }
        kcSession.sessions().removeOfflineUserSession(realm, userSession);
        userSessionPersisterProvider.removeUserSession(userSession.getId(), true);
    }
}
