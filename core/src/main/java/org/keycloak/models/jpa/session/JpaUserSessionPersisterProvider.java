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

package org.keycloak.models.jpa.session;

import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.models.*;
import org.keycloak.models.session.*;
import org.keycloak.models.utils.SessionTimeoutHelper;
import org.keycloak.storage.StorageId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JpaUserSessionPersisterProvider implements UserSessionPersisterProvider {
    private static final Logger LOG = LoggerFactory.getLogger(JpaUserSessionPersisterProvider.class);

    private final KeycloakSession session;

    @Autowired
    private PersistentUserSessionRepository persistentUserSessionRepository;
    @Autowired
    private PersistentClientSessionRepository persistentClientSessionRepository;

    public JpaUserSessionPersisterProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void createUserSession(UserSessionModel userSession, boolean offline) {
        PersistentUserSessionAdapter adapter = new PersistentUserSessionAdapter(userSession);
        PersistentUserSessionModel model = adapter.getUpdatedModel();

        PersistentUserSession entity = new PersistentUserSession();
        entity.setUserSessionId(model.getUserSessionId());
        entity.setCreatedOn(model.getStarted());
        entity.setRealmId(adapter.getRealm().getId());
        entity.setUserId(adapter.getUser().getId());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        entity.setLastSessionRefresh(model.getLastSessionRefresh());
        entity.setData(model.getData());
        persistentUserSessionRepository.save(entity);
    }

    @Override
    public void createClientSession(AuthenticatedClientSessionModel clientSession, boolean offline) {
        PersistentAuthenticatedClientSessionAdapter adapter = new PersistentAuthenticatedClientSessionAdapter(clientSession);
        PersistentClientSessionModel model = adapter.getUpdatedModel();

        PersistentClientSession entity = new PersistentClientSession();
        StorageId clientStorageId = new StorageId(clientSession.getClient().getId());
        if (clientStorageId.isLocal()) {
            entity.setClientId(clientStorageId.getId());
            entity.setClientStorageProvider(PersistentClientSession.LOCAL);
            entity.setExternalClientId(PersistentClientSession.LOCAL);

        } else {
            entity.setClientId(PersistentClientSession.EXTERNAL);
            entity.setClientStorageProvider(clientStorageId.getProviderId());
            entity.setExternalClientId(clientStorageId.getExternalId());
        }
        entity.setTimestamp(clientSession.getTimestamp());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        entity.setUserSessionId(clientSession.getUserSession().getId());
        entity.setData(model.getData());
        persistentClientSessionRepository.save(entity);
    }

    @Override
    public void removeUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);

        persistentClientSessionRepository.deleteClientSessionsByUserSession(userSessionId, offlineStr);
        persistentUserSessionRepository.deleteByUserSessionIdAndOffline(userSessionId, offlineStr);
    }

    @Override
    public void removeClientSession(String userSessionId, String clientUUID, boolean offline) {
        String offlineStr = offlineToString(offline);
        StorageId clientStorageId = new StorageId(clientUUID);
        String clientId = PersistentClientSession.EXTERNAL;
        String clientStorageProvider = PersistentClientSession.LOCAL;
        String externalId = PersistentClientSession.LOCAL;
        if (clientStorageId.isLocal()) {
            clientId = clientUUID;
        } else {
            clientStorageProvider = clientStorageId.getProviderId();
            externalId = clientStorageId.getExternalId();

        }
        PersistentClientSession sessionEntity = persistentClientSessionRepository.findByKey(userSessionId, clientId, clientStorageProvider, externalId, offlineStr);
        if (sessionEntity != null) {
            persistentClientSessionRepository.delete(sessionEntity);

            // Remove userSession if it was last clientSession
            List<PersistentClientSession> clientSessions = getClientSessionsByUserSession(sessionEntity.getUserSessionId(), offline);
            if (clientSessions.size() == 0) {
                offlineStr = offlineToString(offline);
                PersistentUserSession userSessionEntity = persistentUserSessionRepository.findByKey(sessionEntity.getUserSessionId(), offlineStr);
                if (userSessionEntity != null) {
                    persistentUserSessionRepository.delete(userSessionEntity);
                }
            }
        }
    }

    private List<PersistentClientSession> getClientSessionsByUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);
        return persistentClientSessionRepository.findClientSessionsByUserSession(userSessionId, offlineStr);
    }

    @Override
    public void onRealmRemoved(RealmModel realm) {
        persistentClientSessionRepository.deleteClientSessionsByRealm(realm.getId());
        persistentUserSessionRepository.deleteUserSessionsByRealm(realm.getId());
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        onClientRemoved(client.getId());
    }

    private void onClientRemoved(String clientUUID) {
        StorageId clientStorageId = new StorageId(clientUUID);
        if (clientStorageId.isLocal()) {
            persistentClientSessionRepository.deleteClientSessionsByClient(clientUUID);
        } else {
            persistentClientSessionRepository.deleteClientSessionsByExternalClient(clientStorageId.getProviderId(), clientStorageId.getExternalId());
        }
    }

    @Override
    public void onUserRemoved(RealmModel realm, UserModel user) {
        onUserRemoved(realm, user.getId());
    }

    private void onUserRemoved(RealmModel realm, String userId) {
        persistentClientSessionRepository.deleteClientSessionsByUser(userId);
        persistentUserSessionRepository.deleteUserSessionsByUser(userId);
    }

    @Override
    public void updateLastSessionRefreshes(RealmModel realm, int lastSessionRefresh, Collection<String> userSessionIds, boolean offline) {
        String offlineStr = offlineToString(offline);
        int us = persistentUserSessionRepository.updateUserSessionLastSessionRefresh(realm.getId(), lastSessionRefresh, offlineStr, userSessionIds);

        LOG.debug("Updated lastSessionRefresh of {} user sessions in realm '{}'", us, realm.getName());
    }

    @Override
    public void removeExpired(RealmModel realm) {
        int expiredOffline = Time.currentTime() - realm.getOfflineSessionIdleTimeout() - SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;

        String offlineStr = offlineToString(true);

        LOG.trace("Trigger removing expired user sessions for realm '{}'", realm.getName());
        int us = persistentClientSessionRepository.deleteExpiredClientSessions(realm.getId(), expiredOffline, offlineStr);
        int cs = persistentUserSessionRepository.deleteExpiredUserSessions(realm.getId(), expiredOffline, offlineStr);

        LOG.debug("Removed {} expired user sessions and {} expired client sessions in realm '{}'", us, cs, realm.getName());
    }

    @Override
    public List<? extends UserSessionModel> loadUserSessions(int firstResult, int maxResults, boolean offline, int lastCreatedOn, String lastUserSessionId) {
        String offlineStr = offlineToString(offline);
        List<PersistentUserSessionAdapter> result = persistentUserSessionRepository.findUserSessions(offlineStr, lastCreatedOn, lastUserSessionId)
                .map(this::toAdapter)
                .collect(Collectors.toList());

        Map<String, PersistentUserSessionAdapter> sessionsById = result.stream()
                .collect(Collectors.toMap(UserSessionModel::getId, Function.identity()));

        Set<String> userSessionIds = sessionsById.keySet();

        Set<String> removedClientUUIDs = new HashSet<>();

        if (!userSessionIds.isEmpty()) {
            List<PersistentClientSession> clientSessions = persistentClientSessionRepository.findClientSessionsByUserSessions(userSessionIds, offlineStr);
            for (PersistentClientSession clientSession : clientSessions) {
                PersistentUserSessionAdapter userSession = sessionsById.get(clientSession.getUserSessionId());

                PersistentAuthenticatedClientSessionAdapter clientSessAdapter = toAdapter(userSession.getRealm(), userSession, clientSession);
                Map<String, AuthenticatedClientSessionModel> currentClientSessions = userSession.getAuthenticatedClientSessions();

                // Case when client was removed in the meantime
                if (clientSessAdapter.getClient() == null) {
                    removedClientUUIDs.add(clientSession.getClientId());
                } else {
                    currentClientSessions.put(clientSession.getClientId(), clientSessAdapter);
                }
            }
        }

        for (String clientUUID : removedClientUUIDs) {
            onClientRemoved(clientUUID);
        }

        return result;
    }

    private PersistentUserSessionAdapter toAdapter(PersistentUserSession entity) {
        RealmModel realm = session.realms().getRealm(entity.getRealmId());
        return toAdapter(realm, entity);
    }

    private PersistentUserSessionAdapter toAdapter(RealmModel realm, PersistentUserSession entity) {
        PersistentUserSessionModel model = new PersistentUserSessionModel();
        model.setUserSessionId(entity.getUserSessionId());
        model.setStarted(entity.getCreatedOn());
        model.setLastSessionRefresh(entity.getLastSessionRefresh());
        model.setData(entity.getData());
        model.setOffline(offlineFromString(entity.getOffline()));

        Map<String, AuthenticatedClientSessionModel> clientSessions = new HashMap<>();
        return new PersistentUserSessionAdapter(session, model, realm, entity.getUserId(), clientSessions);
    }

    private PersistentAuthenticatedClientSessionAdapter toAdapter(RealmModel realm, PersistentUserSessionAdapter userSession, PersistentClientSession entity) {
        String clientId = entity.getClientId();
        if (!entity.getExternalClientId().equals("local")) {
            clientId = new StorageId(entity.getClientId(), entity.getExternalClientId()).getId();
        }
        ClientModel client = realm.getClientById(clientId);

        PersistentClientSessionModel model = new PersistentClientSessionModel();
        model.setClientId(clientId);
        model.setUserSessionId(userSession.getId());
        model.setUserId(userSession.getUserId());
        model.setTimestamp(entity.getTimestamp());
        model.setData(entity.getData());
        return new PersistentAuthenticatedClientSessionAdapter(model, realm, client, userSession);
    }

    @Override
    public int getUserSessionsCount(boolean offline) {
        String offlineStr = offlineToString(offline);
        return persistentUserSessionRepository.findUserSessionsCount(offlineStr);
    }

    @Override
    public void close() {

    }

    private String offlineToString(boolean offline) {
        return offline ? "1" : "0";
    }

    private boolean offlineFromString(String offlineStr) {
        return "1".equals(offlineStr);
    }
}
