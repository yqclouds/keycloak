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

package org.keycloak.models.sessions.infinispan.changes.sessions;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.SessionUpdateTask;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CrossDCLastSessionRefreshChecker {

    public static final Logger LOG = LoggerFactory.getLogger(CrossDCLastSessionRefreshChecker.class);

    private final CrossDCLastSessionRefreshStore store;
    private final CrossDCLastSessionRefreshStore offlineStore;


    public CrossDCLastSessionRefreshChecker(CrossDCLastSessionRefreshStore store, CrossDCLastSessionRefreshStore offlineStore) {
        this.store = store;
        this.offlineStore = offlineStore;
    }


    public SessionUpdateTask.CrossDCMessageStatus shouldSaveUserSessionToRemoteCache(
            KeycloakSession kcSession, RealmModel realm, SessionEntityWrapper<UserSessionEntity> sessionWrapper, boolean offline, int newLastSessionRefresh) {

        SessionUpdateTask.CrossDCMessageStatus baseChecks = baseChecks(kcSession, realm, offline);
        if (baseChecks != null) {
            return baseChecks;
        }

        String userSessionId = sessionWrapper.getEntity().getId();

        if (offline) {
            Integer lsrr = sessionWrapper.getLocalMetadataNoteInt(UserSessionEntity.LAST_SESSION_REFRESH_REMOTE);
            if (lsrr == null) {
                lsrr = sessionWrapper.getEntity().getStarted();
            }

            if (lsrr + (realm.getOfflineSessionIdleTimeout() / 2) <= newLastSessionRefresh) {
                LOG.debug("We are going to write remotely userSession {}. Remote last session refresh: {}, New last session refresh: {}",
                        userSessionId, lsrr, newLastSessionRefresh);
                return SessionUpdateTask.CrossDCMessageStatus.SYNC;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Skip writing last session refresh to the remoteCache. Session {} newLastSessionRefresh {}", userSessionId, newLastSessionRefresh);
        }

        CrossDCLastSessionRefreshStore storeToUse = offline ? offlineStore : store;
        storeToUse.putLastSessionRefresh(kcSession, userSessionId, realm.getId(), newLastSessionRefresh);

        return SessionUpdateTask.CrossDCMessageStatus.NOT_NEEDED;
    }


    public SessionUpdateTask.CrossDCMessageStatus shouldSaveClientSessionToRemoteCache(
            KeycloakSession kcSession, RealmModel realm, SessionEntityWrapper<AuthenticatedClientSessionEntity> sessionWrapper, UserSessionModel userSession, boolean offline, int newTimestamp) {

        SessionUpdateTask.CrossDCMessageStatus baseChecks = baseChecks(kcSession, realm, offline);
        if (baseChecks != null) {
            return baseChecks;
        }

        UUID clientSessionId = sessionWrapper.getEntity().getId();

        if (offline) {
            Integer lsrr = sessionWrapper.getLocalMetadataNoteInt(AuthenticatedClientSessionEntity.LAST_TIMESTAMP_REMOTE);
            if (lsrr == null) {
                lsrr = userSession.getStarted();
            }

            if (lsrr + (realm.getOfflineSessionIdleTimeout() / 2) <= newTimestamp) {
                LOG.debug("We are going to write remotely for clientSession {}. Remote timestamp: {}, New timestamp: {}",
                        clientSessionId, lsrr, newTimestamp);
                return SessionUpdateTask.CrossDCMessageStatus.SYNC;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Skip writing timestamp to the remoteCache. ClientSession {} timestamp %d", clientSessionId, newTimestamp);
        }

        return SessionUpdateTask.CrossDCMessageStatus.NOT_NEEDED;
    }


    private SessionUpdateTask.CrossDCMessageStatus baseChecks(KeycloakSession kcSession, RealmModel realm, boolean offline) {
        // revokeRefreshToken always writes everything to remoteCache immediately
        if (realm.isRevokeRefreshToken()) {
            return SessionUpdateTask.CrossDCMessageStatus.SYNC;
        }

        // We're likely not in cross-dc environment. Doesn't matter what we return
        CrossDCLastSessionRefreshStore storeToUse = offline ? offlineStore : store;
        if (storeToUse == null) {
            return SessionUpdateTask.CrossDCMessageStatus.SYNC;
        }

        // Received the message from the other DC that we should update the lastSessionRefresh in local cluster
        Boolean ignoreRemoteCacheUpdate = (Boolean) kcSession.getAttribute(CrossDCLastSessionRefreshListener.IGNORE_REMOTE_CACHE_UPDATE);
        if (ignoreRemoteCacheUpdate != null && ignoreRemoteCacheUpdate) {
            return SessionUpdateTask.CrossDCMessageStatus.NOT_NEEDED;
        }

        return null;
    }

}
