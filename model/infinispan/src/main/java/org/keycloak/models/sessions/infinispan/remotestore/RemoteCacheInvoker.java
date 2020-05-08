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

package org.keycloak.models.sessions.infinispan.remotestore;

import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.VersionedValue;
import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.keycloak.common.util.Retry;
import org.keycloak.connections.infinispan.TopologyInfo;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.SessionUpdateTask;
import org.keycloak.models.sessions.infinispan.entities.SessionEntity;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RemoteCacheInvoker {

    public static final Logger LOG = LoggerFactory.getLogger(RemoteCacheInvoker.class);

    private final Map<String, RemoteCacheContext> remoteCaches = new HashMap<>();


    public void addRemoteCache(String cacheName, RemoteCache remoteCache, MaxIdleTimeLoader maxIdleLoader) {
        RemoteCacheContext ctx = new RemoteCacheContext(remoteCache, maxIdleLoader);
        remoteCaches.put(cacheName, ctx);
    }

    public Set<String> getRemoteCacheNames() {
        return Collections.unmodifiableSet(remoteCaches.keySet());
    }

    @Autowired
    private InfinispanUtil infinispanUtil;

    public <K, V extends SessionEntity> void runTask(KeycloakSession kcSession, RealmModel realm, String cacheName, K key, SessionUpdateTask<V> task, SessionEntityWrapper<V> sessionWrapper) {
        RemoteCacheContext context = remoteCaches.get(cacheName);
        if (context == null) {
            return;
        }

        V session = sessionWrapper.getEntity();

        SessionUpdateTask.CacheOperation operation = task.getOperation(session);
        SessionUpdateTask.CrossDCMessageStatus status = task.getCrossDCMessageStatus(sessionWrapper);

        if (status == SessionUpdateTask.CrossDCMessageStatus.NOT_NEEDED) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Skip writing to remoteCache for entity '{}' of cache '{}' and operation '{}'", key, cacheName, operation);
            }
            return;
        }

        long loadedMaxIdleTimeMs = context.maxIdleTimeLoader.getMaxIdleTimeMs(realm);

        // Increase the timeout to ensure that entry won't expire on remoteCache in case that write of some entities to remoteCache is postponed (eg. userSession.lastSessionRefresh)
        final long maxIdleTimeMs = loadedMaxIdleTimeMs + 1800000;

        if (LOG.isTraceEnabled()) {
            LOG.trace("Running task '{}' on remote cache '{}' . Key is '{}'", operation, cacheName, key);
        }

        TopologyInfo topology = infinispanUtil.getTopologyInfo(kcSession);

        Retry.executeWithBackoff((int iteration) -> {

            try {
                runOnRemoteCache(topology, context.remoteCache, maxIdleTimeMs, key, task, sessionWrapper);
            } catch (HotRodClientException re) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed running task '{}' on remote cache '{}' . Key: '{}', iteration '{}'. Will try to retry the task",
                            operation, cacheName, key, iteration);
                }

                // Rethrow the exception. Retry will take care of handle the exception and eventually retry the operation.
                throw re;
            }

        }, 10, 10);
    }


    private <K, V extends SessionEntity> void runOnRemoteCache(TopologyInfo topology, RemoteCache<K, SessionEntityWrapper<V>> remoteCache, long maxIdleMs, K key, SessionUpdateTask<V> task, SessionEntityWrapper<V> sessionWrapper) {
        final V session = sessionWrapper.getEntity();
        SessionUpdateTask.CacheOperation operation = task.getOperation(session);

        switch (operation) {
            case REMOVE:
                remoteCache.remove(key);
                break;
            case ADD:
                remoteCache.put(key, sessionWrapper.forTransport(), task.getLifespanMs(), TimeUnit.MILLISECONDS, maxIdleMs, TimeUnit.MILLISECONDS);
                break;
            case ADD_IF_ABSENT:
                SessionEntityWrapper<V> existing = remoteCache
                        .withFlags(Flag.FORCE_RETURN_VALUE)
                        .putIfAbsent(key, sessionWrapper.forTransport(), -1, TimeUnit.MILLISECONDS, maxIdleMs, TimeUnit.MILLISECONDS);
                if (existing != null) {
                    LOG.debug("Existing entity in remote cache for key: {} . Will update it", key);

                    replace(topology, remoteCache, task.getLifespanMs(), maxIdleMs, key, task);
                }
                break;
            case REPLACE:
                replace(topology, remoteCache, task.getLifespanMs(), maxIdleMs, key, task);
                break;
            default:
                throw new IllegalStateException("Unsupported state " + operation);
        }
    }


    private <K, V extends SessionEntity> void replace(TopologyInfo topology, RemoteCache<K, SessionEntityWrapper<V>> remoteCache, long lifespanMs, long maxIdleMs, K key, SessionUpdateTask<V> task) {
        boolean replaced = false;
        int replaceIteration = 0;
        while (!replaced && replaceIteration < InfinispanUtil.MAXIMUM_REPLACE_RETRIES) {
            replaceIteration++;

            VersionedValue<SessionEntityWrapper<V>> versioned = remoteCache.getWithMetadata(key);
            if (versioned == null) {
                LOG.warn("Not found entity to replace for key '{}'", key);
                return;
            }

            SessionEntityWrapper<V> sessionWrapper = versioned.getValue();
            final V session = sessionWrapper.getEntity();

            // Run task on the remote session
            task.runUpdate(session);

            if (LOG.isTraceEnabled()) {
                LOG.trace("{}: Before replaceWithVersion. Entity to write version {}: {}", logTopologyData(topology, replaceIteration),
                        versioned.getVersion(), session);
            }

            replaced = remoteCache.replaceWithVersion(key, SessionEntityWrapper.forTransport(session), versioned.getVersion(), lifespanMs, TimeUnit.MILLISECONDS, maxIdleMs, TimeUnit.MILLISECONDS);

            if (!replaced) {
                LOG.debug("{}: Failed to replace entity '{}' version {}. Will retry again", logTopologyData(topology, replaceIteration), key, versioned.getVersion());
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("{}: Replaced entity version {} in remote cache: {}", logTopologyData(topology, replaceIteration), versioned.getVersion(), session);
                }
            }
        }

        if (!replaced) {
            LOG.warn("Failed to replace entity '{}' in remote cache '{}'", key, remoteCache.getName());
        }
    }


    private String logTopologyData(TopologyInfo topology, int iteration) {
        return topology.toString() + ", replaceIteration: " + iteration;
    }


    @FunctionalInterface
    public interface MaxIdleTimeLoader {

        long getMaxIdleTimeMs(RealmModel realm);

    }

    private class RemoteCacheContext {

        private final RemoteCache remoteCache;
        private final MaxIdleTimeLoader maxIdleTimeLoader;

        public RemoteCacheContext(RemoteCache remoteCache, MaxIdleTimeLoader maxIdleLoader) {
            this.remoteCache = remoteCache;
            this.maxIdleTimeLoader = maxIdleLoader;
        }

    }


}
