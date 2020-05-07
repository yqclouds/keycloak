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

package org.keycloak.models.sessions.infinispan;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.persistence.remote.RemoteStore;
import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.common.util.Environment;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.sessions.CrossDCLastSessionRefreshStore;
import org.keycloak.models.sessions.infinispan.changes.sessions.CrossDCLastSessionRefreshStoreFactory;
import org.keycloak.models.sessions.infinispan.changes.sessions.PersisterLastSessionRefreshStore;
import org.keycloak.models.sessions.infinispan.changes.sessions.PersisterLastSessionRefreshStoreFactory;
import org.keycloak.models.sessions.infinispan.entities.*;
import org.keycloak.models.sessions.infinispan.events.*;
import org.keycloak.models.sessions.infinispan.initializer.CacheInitializer;
import org.keycloak.models.sessions.infinispan.initializer.DBLockBasedCacheInitializer;
import org.keycloak.models.sessions.infinispan.initializer.InfinispanCacheInitializer;
import org.keycloak.models.sessions.infinispan.initializer.OfflinePersistentUserSessionLoader;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheInvoker;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheSessionListener;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheSessionsLoader;
import org.keycloak.models.sessions.infinispan.util.InfinispanKeyGenerator;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.ResetTimeOffsetEvent;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.Serializable;
import java.util.Set;
import java.util.UUID;

@Component("InfinispanUserSessionProviderFactory")
@ProviderFactory(id = "infinispan", providerClasses = UserSessionProvider.class)
public class InfinispanUserSessionProviderFactory implements UserSessionProviderFactory {

    public static final String PROVIDER_ID = "infinispan";
    public static final String REALM_REMOVED_SESSION_EVENT = "REALM_REMOVED_EVENT_SESSIONS";
    public static final String CLIENT_REMOVED_SESSION_EVENT = "CLIENT_REMOVED_SESSION_SESSIONS";
    public static final String REMOVE_USER_SESSIONS_EVENT = "REMOVE_USER_SESSIONS_EVENT";
    public static final String REMOVE_ALL_LOGIN_FAILURES_EVENT = "REMOVE_ALL_LOGIN_FAILURES_EVENT";
    private static final Logger log = Logger.getLogger(InfinispanUserSessionProviderFactory.class);

    private RemoteCacheInvoker remoteCacheInvoker;
    private CrossDCLastSessionRefreshStore lastSessionRefreshStore;
    private CrossDCLastSessionRefreshStore offlineLastSessionRefreshStore;
    private PersisterLastSessionRefreshStore persisterLastSessionRefreshStore;
    private InfinispanKeyGenerator keyGenerator;

    @Value("${maxErrors}")
    private int maxErrors = 20;
    @Value("${sessionsPerSegment}")
    private int sessionsPerSegment = 64;
    @Value("${sessionsPreloadTimeoutInSeconds}")
    private Integer sessionsPreloadTimeoutInSeconds = null;

    @Autowired
    private KeycloakSessionFactory sessionFactory;
    @Autowired
    private InfinispanConnectionProvider connectionProvider;
    @Autowired
    private ClusterProvider clusterProvider;

    @Override
    public InfinispanUserSessionProvider create(KeycloakSession session) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = connectionProvider.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
        Cache<String, SessionEntityWrapper<UserSessionEntity>> offlineSessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME);
        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache = connectionProvider.getCache(InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME);
        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> offlineClientSessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME);
        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailures = connectionProvider.getCache(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME);

        return new InfinispanUserSessionProvider(session, remoteCacheInvoker, lastSessionRefreshStore, offlineLastSessionRefreshStore,
                persisterLastSessionRefreshStore, keyGenerator,
                cache, offlineSessionsCache, clientSessionCache, offlineClientSessionsCache, loginFailures);
    }

    @PostConstruct
    public void afterPropertiesSet() {
        sessionFactory.register(event -> {
            if (event instanceof PostMigrationEvent) {

                int preloadTransactionTimeout = getTimeoutForPreloadingSessionsSeconds();
                log.debugf("Will preload sessions with transaction timeout %d seconds", preloadTransactionTimeout);

                KeycloakModelUtils.runJobInTransactionWithTimeout(sessionFactory, (KeycloakSession session) -> {

                    keyGenerator = new InfinispanKeyGenerator();
                    checkRemoteCaches(session);
                    loadPersistentSessions(sessionFactory, getMaxErrors(), getSessionsPerSegment());
                    registerClusterListeners(session);
                    loadSessionsFromRemoteCaches(session);

                }, preloadTransactionTimeout);

            } else if (event instanceof UserModel.UserRemovedEvent) {
                UserModel.UserRemovedEvent userRemovedEvent = (UserModel.UserRemovedEvent) event;

                InfinispanUserSessionProvider provider = (InfinispanUserSessionProvider) userRemovedEvent.getSession().getProvider(UserSessionProvider.class, getId());
                provider.onUserRemoved(userRemovedEvent.getRealm(), userRemovedEvent.getUser());
            } else if (event instanceof ResetTimeOffsetEvent) {
                if (persisterLastSessionRefreshStore != null) {
                    persisterLastSessionRefreshStore.reset();
                }
                if (lastSessionRefreshStore != null) {
                    lastSessionRefreshStore.reset();
                }
                if (offlineLastSessionRefreshStore != null) {
                    offlineLastSessionRefreshStore.reset();
                }
            }
        });
    }

    // Max count of worker errors. Initialization will end with exception when this number is reached
    private int getMaxErrors() {
        return this.maxErrors;
    }

    // Count of sessions to be computed in each segment
    private int getSessionsPerSegment() {
        return this.sessionsPerSegment;
    }

    private int getTimeoutForPreloadingSessionsSeconds() {
        Integer timeout = this.sessionsPreloadTimeoutInSeconds;
        return timeout != null ? timeout : Environment.getServerStartupTimeout();
    }


    @Override
    public void loadPersistentSessions(final KeycloakSessionFactory sessionFactory, final int maxErrors, final int sessionsPerSegment) {
        log.debug("Start pre-loading userSessions from persistent storage");

        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            Cache<String, Serializable> workCache = connectionProvider.getCache(InfinispanConnectionProvider.WORK_CACHE_NAME);

            InfinispanCacheInitializer ispnInitializer = new InfinispanCacheInitializer(sessionFactory, workCache,
                    new OfflinePersistentUserSessionLoader(sessionsPerSegment), "offlineUserSessions", sessionsPerSegment, maxErrors);

            // DB-lock to ensure that persistent sessions are loaded from DB just on one DC. The other DCs will load them from remote cache.
            CacheInitializer initializer = new DBLockBasedCacheInitializer(session, ispnInitializer);

            initializer.initCache();
            initializer.loadSessions();

            // Initialize persister for periodically doing bulk DB updates of lastSessionRefresh timestamps of refreshed sessions
            persisterLastSessionRefreshStore = new PersisterLastSessionRefreshStoreFactory().createAndInit(true);
        });

        log.debug("Pre-loading userSessions from persistent storage finished");
    }


    protected void registerClusterListeners(KeycloakSession session) {
        KeycloakSessionFactory sessionFactory = session.getSessionFactory();
        clusterProvider.registerListener(REALM_REMOVED_SESSION_EVENT, new AbstractUserSessionClusterListener<RealmRemovedSessionEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanUserSessionProvider provider, RealmRemovedSessionEvent sessionEvent) {
                provider.onRealmRemovedEvent(sessionEvent.getRealmId());
            }
        });

        clusterProvider.registerListener(CLIENT_REMOVED_SESSION_EVENT, new AbstractUserSessionClusterListener<ClientRemovedSessionEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanUserSessionProvider provider, ClientRemovedSessionEvent sessionEvent) {
                provider.onClientRemovedEvent(sessionEvent.getRealmId(), sessionEvent.getClientUuid());
            }
        });

        clusterProvider.registerListener(REMOVE_USER_SESSIONS_EVENT, new AbstractUserSessionClusterListener<RemoveUserSessionsEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanUserSessionProvider provider, RemoveUserSessionsEvent sessionEvent) {
                provider.onRemoveUserSessionsEvent(sessionEvent.getRealmId());
            }
        });

        clusterProvider.registerListener(REMOVE_ALL_LOGIN_FAILURES_EVENT, new AbstractUserSessionClusterListener<RemoveAllUserLoginFailuresEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanUserSessionProvider provider, RemoveAllUserLoginFailuresEvent sessionEvent) {
                provider.onRemoveAllUserLoginFailuresEvent(sessionEvent.getRealmId());
            }
        });

        log.debug("Registered cluster listeners");
    }

    protected void checkRemoteCaches(KeycloakSession session) {
        this.remoteCacheInvoker = new RemoteCacheInvoker();

        Cache<String, SessionEntityWrapper<UserSessionEntity>> sessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME);
        boolean sessionsRemoteCache = checkRemoteCache(session, sessionsCache, (RealmModel realm) -> {
            // We won't write to the remoteCache during token refresh, so the timeout needs to be longer.
            return realm.getSsoSessionMaxLifespan() * 1000;
        });

        if (sessionsRemoteCache) {
            lastSessionRefreshStore = new CrossDCLastSessionRefreshStoreFactory().createAndInit(session, sessionsCache, false);
        }

        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME);
        checkRemoteCache(session, clientSessionsCache, (RealmModel realm) -> {
            // We won't write to the remoteCache during token refresh, so the timeout needs to be longer.
            return realm.getSsoSessionMaxLifespan() * 1000;
        });

        Cache<String, SessionEntityWrapper<UserSessionEntity>> offlineSessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME);
        boolean offlineSessionsRemoteCache = checkRemoteCache(session, offlineSessionsCache, (RealmModel realm) -> {
            return realm.getOfflineSessionIdleTimeout() * 1000;
        });

        if (offlineSessionsRemoteCache) {
            offlineLastSessionRefreshStore = new CrossDCLastSessionRefreshStoreFactory().createAndInit(session, offlineSessionsCache, true);
        }

        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> offlineClientSessionsCache = connectionProvider.getCache(InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME);
        checkRemoteCache(session, offlineClientSessionsCache, (RealmModel realm) -> {
            return realm.getOfflineSessionIdleTimeout() * 1000;
        });

        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailuresCache = connectionProvider.getCache(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME);
        checkRemoteCache(session, loginFailuresCache, (RealmModel realm) -> {
            return realm.getMaxDeltaTimeSeconds() * 1000;
        });
    }

    private <K, V extends SessionEntity> boolean checkRemoteCache(KeycloakSession session, Cache<K, SessionEntityWrapper<V>> ispnCache, RemoteCacheInvoker.MaxIdleTimeLoader maxIdleLoader) {
        Set<RemoteStore> remoteStores = InfinispanUtil.getRemoteStores(ispnCache);

        if (remoteStores.isEmpty()) {
            log.debugf("No remote store configured for cache '%s'", ispnCache.getName());
            return false;
        } else {
            log.infof("Remote store configured for cache '%s'", ispnCache.getName());

            RemoteCache<K, SessionEntityWrapper<V>> remoteCache = (RemoteCache) remoteStores.iterator().next().getRemoteCache();

            if (remoteCache == null) {
                throw new IllegalStateException("No remote cache available for the infinispan cache: " + ispnCache.getName());
            }

            remoteCacheInvoker.addRemoteCache(ispnCache.getName(), remoteCache, maxIdleLoader);

            RemoteCacheSessionListener hotrodListener = RemoteCacheSessionListener.createListener(session, ispnCache, remoteCache);
            remoteCache.addClientListener(hotrodListener);
            return true;
        }
    }


    private void loadSessionsFromRemoteCaches(KeycloakSession session) {
        for (String cacheName : remoteCacheInvoker.getRemoteCacheNames()) {
            loadSessionsFromRemoteCache(session.getSessionFactory(), cacheName, getSessionsPerSegment(), getMaxErrors());
        }
    }


    private void loadSessionsFromRemoteCache(final KeycloakSessionFactory sessionFactory, String cacheName, final int sessionsPerSegment, final int maxErrors) {
        log.debugf("Check pre-loading sessions from remote cache '%s'", cacheName);

        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            Cache<String, Serializable> workCache = connectionProvider.getCache(InfinispanConnectionProvider.WORK_CACHE_NAME);

            InfinispanCacheInitializer initializer = new InfinispanCacheInitializer(sessionFactory, workCache,
                    new RemoteCacheSessionsLoader(cacheName, sessionsPerSegment), "remoteCacheLoad::" + cacheName, sessionsPerSegment, maxErrors);

            initializer.initCache();
            initializer.loadSessions();
        });

        log.debugf("Pre-loading sessions from remote cache '%s' finished", cacheName);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

