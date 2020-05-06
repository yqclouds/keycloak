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

package org.keycloak.connections.infinispan;

import org.infinispan.client.hotrod.ProtocolVersion;
import org.infinispan.commons.util.FileLookup;
import org.infinispan.commons.util.FileLookupFactory;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.Configuration;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.eviction.EvictionStrategy;
import org.infinispan.eviction.EvictionType;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.persistence.remote.configuration.RemoteStoreConfigurationBuilder;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.infinispan.transaction.LockingMode;
import org.infinispan.transaction.TransactionMode;
import org.infinispan.transaction.lookup.EmbeddedTransactionManagerLookup;
import org.jboss.logging.Logger;
import org.jgroups.JChannel;
import org.keycloak.cluster.infinispan.KeycloakHotRodMarshallerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component
@ProviderFactory(id = "default", providerClasses = InfinispanConnectionProvider.class)
public class DefaultInfinispanConnectionProviderFactory implements InfinispanConnectionProviderFactory {
    protected static final Logger logger = Logger.getLogger(DefaultInfinispanConnectionProviderFactory.class);
    private static final Object CHANNEL_INIT_SYNCHRONIZER = new Object();
    protected EmbeddedCacheManager cacheManager;
    protected RemoteCacheProvider remoteCacheProvider;
    protected boolean containerManaged;
    private TopologyInfo topologyInfo;

    private boolean clustered = false;
    private boolean embedded = false;
    private boolean async = false;
    private boolean allowDuplicateJMXDomains = true;
    private String jgroupsUdpMcastAddr;
    private String sessionsMode = "distributed";
    private int sessionsOwners = 2;
    private int l1Lifespan = 600000;
    private int sessionsSegments = 60;
    private boolean remoteStoreEnabled = false;
    private String remoteStoreHost = "localhost";
    private Integer remoteStorePort = 11222;
    private String hotrodProtocolVersion = "DEFAULT_PROTOCOL_VERSION";
    @Value("${jboss.node.name}")
    private String nodeName;
    @Value("${jboss.site.name}")
    private String siteName;

    @Override
    public InfinispanConnectionProvider create(KeycloakSession session) {
        return new DefaultInfinispanConnectionProvider(cacheManager, remoteCacheProvider, topologyInfo);
    }

    @PostConstruct
    public void afterPropertiesSet() {
        if (cacheManager == null) {
            synchronized (this) {
                if (cacheManager == null) {
                    initEmbedded();

                    logger.infof(topologyInfo.toString());

                    remoteCacheProvider = new RemoteCacheProvider(cacheManager);
                }
            }
        }
    }

    @PreDestroy
    public void destroy() {
        if (cacheManager != null && !containerManaged) {
            cacheManager.stop();
        }
        if (remoteCacheProvider != null) {
            remoteCacheProvider.stop();
        }
        cacheManager = null;
    }

    @Override
    public String getId() {
        return "default";
    }

    protected void initEmbedded() {
        GlobalConfigurationBuilder gcb = new GlobalConfigurationBuilder();

        this.topologyInfo = new TopologyInfo(cacheManager, clustered, nodeName, siteName, true);

        if (clustered) {
            String jgroupsUdpMcastAddr = this.jgroupsUdpMcastAddr; // config.get("jgroupsUdpMcastAddr", System.getProperty(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR));
            configureTransport(gcb, topologyInfo.getMyNodeName(), topologyInfo.getMySiteName(), jgroupsUdpMcastAddr);
            gcb.globalJmxStatistics()
                    .jmxDomain(InfinispanConnectionProvider.JMX_DOMAIN + "-" + topologyInfo.getMyNodeName());
        }

        gcb.globalJmxStatistics().allowDuplicateDomains(allowDuplicateJMXDomains).enable();

        cacheManager = new DefaultCacheManager(gcb.build());
        containerManaged = false;

        logger.debug("Started embedded Infinispan cache container");

        ConfigurationBuilder modelCacheConfigBuilder = new ConfigurationBuilder();
        Configuration modelCacheConfiguration = modelCacheConfigBuilder.build();

        cacheManager.defineConfiguration(InfinispanConnectionProvider.REALM_CACHE_NAME, modelCacheConfiguration);
        cacheManager.defineConfiguration(InfinispanConnectionProvider.AUTHORIZATION_CACHE_NAME, modelCacheConfiguration);
        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_CACHE_NAME, modelCacheConfiguration);

        ConfigurationBuilder sessionConfigBuilder = new ConfigurationBuilder();
        if (clustered) {
            if (sessionsMode.equalsIgnoreCase("replicated")) {
                sessionConfigBuilder.clustering().cacheMode(async ? CacheMode.REPL_ASYNC : CacheMode.REPL_SYNC);
            } else if (sessionsMode.equalsIgnoreCase("distributed")) {
                sessionConfigBuilder.clustering().cacheMode(async ? CacheMode.DIST_ASYNC : CacheMode.DIST_SYNC);
            } else {
                throw new RuntimeException("Invalid value for sessionsMode");
            }

            int owners = this.sessionsOwners;
            logger.debugf("Session owners: %d", owners);

            int l1Lifespan = this.l1Lifespan;
            boolean l1Enabled = l1Lifespan > 0;
            sessionConfigBuilder.clustering()
                    .hash()
                    .numOwners(owners)
                    .numSegments(sessionsSegments)
                    .l1()
                    .enabled(l1Enabled)
                    .lifespan(l1Lifespan)
                    .build();
        }

        // Base configuration doesn't contain any remote stores
        Configuration sessionCacheConfigurationBase = sessionConfigBuilder.build();

        boolean jdgEnabled = this.remoteStoreEnabled;

        if (jdgEnabled) {
            sessionConfigBuilder = new ConfigurationBuilder();
            sessionConfigBuilder.read(sessionCacheConfigurationBase);
            configureRemoteCacheStore(sessionConfigBuilder, async, InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, true);
        }
        Configuration sessionCacheConfiguration = sessionConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, sessionCacheConfiguration);

        if (jdgEnabled) {
            sessionConfigBuilder = new ConfigurationBuilder();
            sessionConfigBuilder.read(sessionCacheConfigurationBase);
            configureRemoteCacheStore(sessionConfigBuilder, async, InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME, true);
        }
        sessionCacheConfiguration = sessionConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME, sessionCacheConfiguration);

        if (jdgEnabled) {
            sessionConfigBuilder = new ConfigurationBuilder();
            sessionConfigBuilder.read(sessionCacheConfigurationBase);
            configureRemoteCacheStore(sessionConfigBuilder, async, InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME, true);
        }
        sessionCacheConfiguration = sessionConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME, sessionCacheConfiguration);

        if (jdgEnabled) {
            sessionConfigBuilder = new ConfigurationBuilder();
            sessionConfigBuilder.read(sessionCacheConfigurationBase);
            configureRemoteCacheStore(sessionConfigBuilder, async, InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME, true);
        }
        sessionCacheConfiguration = sessionConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME, sessionCacheConfiguration);

        if (jdgEnabled) {
            sessionConfigBuilder = new ConfigurationBuilder();
            sessionConfigBuilder.read(sessionCacheConfigurationBase);
            configureRemoteCacheStore(sessionConfigBuilder, async, InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME, true);
        }
        sessionCacheConfiguration = sessionConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME, sessionCacheConfiguration);

        cacheManager.defineConfiguration(InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME, sessionCacheConfigurationBase);

        // Retrieve caches to enforce rebalance
        cacheManager.getCache(InfinispanConnectionProvider.USER_SESSION_CACHE_NAME, true);
        cacheManager.getCache(InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME, true);
        cacheManager.getCache(InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME, true);
        cacheManager.getCache(InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME, true);
        cacheManager.getCache(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME, true);
        cacheManager.getCache(InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME, true);

        ConfigurationBuilder replicationConfigBuilder = new ConfigurationBuilder();
        if (clustered) {
            replicationConfigBuilder.clustering().cacheMode(async ? CacheMode.REPL_ASYNC : CacheMode.REPL_SYNC);
        }

        if (jdgEnabled) {
            configureRemoteCacheStore(replicationConfigBuilder, async, InfinispanConnectionProvider.WORK_CACHE_NAME, false);
        }

        Configuration replicationEvictionCacheConfiguration = replicationConfigBuilder.build();
        cacheManager.defineConfiguration(InfinispanConnectionProvider.WORK_CACHE_NAME, replicationEvictionCacheConfiguration);

        long realmRevisionsMaxEntries = cacheManager.getCache(InfinispanConnectionProvider.REALM_CACHE_NAME).getCacheConfiguration().memory().size();
        realmRevisionsMaxEntries = realmRevisionsMaxEntries > 0
                ? 2 * realmRevisionsMaxEntries
                : InfinispanConnectionProvider.REALM_REVISIONS_CACHE_DEFAULT_MAX;

        cacheManager.defineConfiguration(InfinispanConnectionProvider.REALM_REVISIONS_CACHE_NAME, getRevisionCacheConfig(realmRevisionsMaxEntries));
        cacheManager.getCache(InfinispanConnectionProvider.REALM_REVISIONS_CACHE_NAME, true);

        long userRevisionsMaxEntries = cacheManager.getCache(InfinispanConnectionProvider.USER_CACHE_NAME).getCacheConfiguration().memory().size();
        userRevisionsMaxEntries = userRevisionsMaxEntries > 0
                ? 2 * userRevisionsMaxEntries
                : InfinispanConnectionProvider.USER_REVISIONS_CACHE_DEFAULT_MAX;

        cacheManager.defineConfiguration(InfinispanConnectionProvider.USER_REVISIONS_CACHE_NAME, getRevisionCacheConfig(userRevisionsMaxEntries));
        cacheManager.getCache(InfinispanConnectionProvider.USER_REVISIONS_CACHE_NAME, true);

        cacheManager.defineConfiguration(InfinispanConnectionProvider.KEYS_CACHE_NAME, getKeysCacheConfig());
        cacheManager.getCache(InfinispanConnectionProvider.KEYS_CACHE_NAME, true);

        final ConfigurationBuilder actionTokenCacheConfigBuilder = getActionTokenCacheConfig();
        if (clustered) {
            actionTokenCacheConfigBuilder.clustering().cacheMode(async ? CacheMode.REPL_ASYNC : CacheMode.REPL_SYNC);
        }
        if (jdgEnabled) {
            configureRemoteActionTokenCacheStore(actionTokenCacheConfigBuilder, async);
        }
        cacheManager.defineConfiguration(InfinispanConnectionProvider.ACTION_TOKEN_CACHE, actionTokenCacheConfigBuilder.build());
        cacheManager.getCache(InfinispanConnectionProvider.ACTION_TOKEN_CACHE, true);

        long authzRevisionsMaxEntries = cacheManager.getCache(InfinispanConnectionProvider.AUTHORIZATION_CACHE_NAME).getCacheConfiguration().memory().size();
        authzRevisionsMaxEntries = authzRevisionsMaxEntries > 0
                ? 2 * authzRevisionsMaxEntries
                : InfinispanConnectionProvider.AUTHORIZATION_REVISIONS_CACHE_DEFAULT_MAX;

        cacheManager.defineConfiguration(InfinispanConnectionProvider.AUTHORIZATION_REVISIONS_CACHE_NAME, getRevisionCacheConfig(authzRevisionsMaxEntries));
        cacheManager.getCache(InfinispanConnectionProvider.AUTHORIZATION_REVISIONS_CACHE_NAME, true);
    }

    private Configuration getRevisionCacheConfig(long maxEntries) {
        ConfigurationBuilder cb = new ConfigurationBuilder();
        cb.invocationBatching().enable().transaction().transactionMode(TransactionMode.TRANSACTIONAL);

        // Use Embedded manager even in managed ( wildfly/eap ) environment. We don't want infinispan to participate in global transaction
        cb.transaction().transactionManagerLookup(new EmbeddedTransactionManagerLookup());

        cb.transaction().lockingMode(LockingMode.PESSIMISTIC);

        cb.memory()
                .evictionStrategy(EvictionStrategy.REMOVE)
                .evictionType(EvictionType.COUNT)
                .size(maxEntries);

        return cb.build();
    }

    // Used for cross-data centers scenario. Usually integration with external JDG server, which itself handles communication between DCs.
    private void configureRemoteCacheStore(ConfigurationBuilder builder, boolean async, String cacheName, boolean sessionCache) {
        String jdgServer = this.remoteStoreHost;
        Integer jdgPort = this.remoteStorePort;

        builder.persistence()
                .passivation(false)
                .addStore(RemoteStoreConfigurationBuilder.class)
                .fetchPersistentState(false)
                .ignoreModifications(false)
                .purgeOnStartup(false)
                .preload(false)
                .shared(true)
                .remoteCacheName(cacheName)
                .rawValues(true)
                .forceReturnValues(false)
                .marshaller(KeycloakHotRodMarshallerFactory.class.getName())
                .protocolVersion(getHotrodVersion())
                .addServer()
                .host(jdgServer)
                .port(jdgPort)
//                  .connectionPool()
//                      .maxActive(100)
//                      .exhaustedAction(ExhaustedAction.CREATE_NEW)
                .async()
                .enabled(async);

    }

    private void configureRemoteActionTokenCacheStore(ConfigurationBuilder builder, boolean async) {
        String jdgServer = this.remoteStoreHost;
        Integer jdgPort = this.remoteStorePort;

        builder.persistence()
                .passivation(false)
                .addStore(RemoteStoreConfigurationBuilder.class)
                .fetchPersistentState(false)
                .ignoreModifications(false)
                .purgeOnStartup(false)
                .preload(true)
                .shared(true)
                .remoteCacheName(InfinispanConnectionProvider.ACTION_TOKEN_CACHE)
                .rawValues(true)
                .forceReturnValues(false)
                .marshaller(KeycloakHotRodMarshallerFactory.class.getName())
                .protocolVersion(getHotrodVersion())
                .addServer()
                .host(jdgServer)
                .port(jdgPort)
                .async()
                .enabled(async);

    }

    private ProtocolVersion getHotrodVersion() {
        String hotrodVersionStr = this.hotrodProtocolVersion;
        ProtocolVersion hotrodVersion = ProtocolVersion.parseVersion(hotrodVersionStr);
        if (hotrodVersion == null) {
            hotrodVersion = ProtocolVersion.DEFAULT_PROTOCOL_VERSION;
        }

        logger.debugf("HotRod protocol version: %s", hotrodVersion);

        return hotrodVersion;
    }

    protected Configuration getKeysCacheConfig() {
        ConfigurationBuilder cb = new ConfigurationBuilder();

        cb.memory()
                .evictionStrategy(EvictionStrategy.REMOVE)
                .evictionType(EvictionType.COUNT)
                .size(InfinispanConnectionProvider.KEYS_CACHE_DEFAULT_MAX);

        cb.expiration().maxIdle(InfinispanConnectionProvider.KEYS_CACHE_MAX_IDLE_SECONDS, TimeUnit.SECONDS);
        return cb.build();
    }

    private ConfigurationBuilder getActionTokenCacheConfig() {
        ConfigurationBuilder cb = new ConfigurationBuilder();

        cb.memory()
                .evictionStrategy(EvictionStrategy.NONE)
                .evictionType(EvictionType.COUNT)
                .size(InfinispanConnectionProvider.ACTION_TOKEN_CACHE_DEFAULT_MAX);
        cb.expiration()
                .maxIdle(InfinispanConnectionProvider.ACTION_TOKEN_MAX_IDLE_SECONDS, TimeUnit.SECONDS)
                .wakeUpInterval(InfinispanConnectionProvider.ACTION_TOKEN_WAKE_UP_INTERVAL_SECONDS, TimeUnit.SECONDS);

        return cb;
    }

    protected void configureTransport(GlobalConfigurationBuilder gcb, String nodeName, String siteName, String jgroupsUdpMcastAddr) {
        if (nodeName == null) {
            gcb.transport().defaultTransport();
        } else {
            FileLookup fileLookup = FileLookupFactory.newInstance();

            synchronized (CHANNEL_INIT_SYNCHRONIZER) {
                String originalMcastAddr = System.getProperty(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR);
                if (jgroupsUdpMcastAddr == null) {
                    System.getProperties().remove(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR);
                } else {
                    System.setProperty(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR, jgroupsUdpMcastAddr);
                }
                try {
                    // Compatibility with Wildfly
                    JChannel channel = new JChannel(fileLookup.lookupFileLocation("default-configs/default-jgroups-udp.xml", this.getClass().getClassLoader()));
                    channel.setName(nodeName);
                    JGroupsTransport transport = new JGroupsTransport(channel);

                    gcb.transport()
                            .nodeName(nodeName)
                            .siteId(siteName)
                            .transport(transport)
                            .globalJmxStatistics()
                            .jmxDomain(InfinispanConnectionProvider.JMX_DOMAIN + "-" + nodeName)
                            .enable()
                    ;

                    logger.infof("Configured jgroups transport with the channel name: %s", nodeName);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    if (originalMcastAddr == null) {
                        System.getProperties().remove(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR);
                    } else {
                        System.setProperty(InfinispanConnectionProvider.JGROUPS_UDP_MCAST_ADDR, originalMcastAddr);
                    }
                }
            }
        }
    }

}
