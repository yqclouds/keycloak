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

package org.keycloak.connections.infinispan;

import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.configuration.Configuration;
import org.infinispan.client.hotrod.configuration.ConfigurationBuilder;
import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.infinispan.manager.EmbeddedCacheManager;
import org.keycloak.common.util.reflections.Reflections;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.*;
import javax.security.sasl.RealmCallback;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Get either just remoteCache associated with remoteStore associated with infinispan cache of given name. If security is enabled, then
 * return secured remoteCache based on the template provided by remoteStore configuration but with added "authentication" configuration
 * of secured hotrod endpoint (RemoteStore doesn't yet allow to configure "security" of hotrod endpoints)
 * <p>
 * TODO: Remove this class once we upgrade to infinispan version, which allows to configure security for remoteStore itself
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RemoteCacheProvider {
    protected static final Logger LOG = LoggerFactory.getLogger(RemoteCacheProvider.class);

    public static final String SCRIPT_CACHE_NAME = "___script_cache";

    private final EmbeddedCacheManager cacheManager;

    private final Map<String, RemoteCache> availableCaches = new HashMap<>();

    // Enlist secured managers, which are managed by us and should be shutdown on stop
    private final Map<String, RemoteCacheManager> managedManagers = new HashMap<>();

    private Boolean remoteStoreSecurityEnabled = null;
    private String remoteStoreSecurityServerName = "keycloak-jdg-server";
    private String remoteStoreSecurityRealm = "AllowScriptManager";
    private String remoteStoreSecurityUsername = "___script_manager";
    private String remoteStoreSecurityPassword = "not-so-secret-password";

    public RemoteCacheProvider(EmbeddedCacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public RemoteCache getRemoteCache(String cacheName) {
        if (availableCaches.get(cacheName) == null) {
            synchronized (this) {
                if (availableCaches.get(cacheName) == null) {
                    RemoteCache remoteCache = loadRemoteCache(cacheName);
                    availableCaches.put(cacheName, remoteCache);
                }
            }
        }

        return availableCaches.get(cacheName);
    }

    public void stop() {
        LOG.debug("Shutdown {} registered secured remoteCache managers", managedManagers.size());

        for (RemoteCacheManager mgr : managedManagers.values()) {
            mgr.stop();
        }
    }


    protected synchronized RemoteCache loadRemoteCache(String cacheName) {
        RemoteCache remoteCache = InfinispanUtil.getRemoteCache(cacheManager.getCache(cacheName));

        Boolean remoteStoreSecurity = this.remoteStoreSecurityEnabled;
        if (remoteStoreSecurity == null) {
            try {
                LOG.debug("Detecting remote security settings of HotRod server, cache {}. Disable by explicitly setting \"remoteStoreSecurityEnabled\" property in spi=connectionsInfinispan/provider=default", cacheName);
                remoteStoreSecurity = false;
                final RemoteCache<Object, Object> scriptCache = remoteCache.getRemoteCacheManager().getCache(SCRIPT_CACHE_NAME);
                if (scriptCache == null) {
                    LOG.debug("Cannot detect remote security settings of HotRod server, disabling.");
                } else {
                    scriptCache.containsKey("");
                }
            } catch (HotRodClientException ex) {
                LOG.debug("Seems that HotRod server requires authentication, enabling.");
                remoteStoreSecurity = true;
            }
        }

        if (remoteStoreSecurity) {
            LOG.info("Remote store security for cache {} is enabled. Disable by setting \"remoteStoreSecurityEnabled\" property to \"false\" in spi=connectionsInfinispan/provider=default", cacheName);
            RemoteCacheManager securedMgr = getOrCreateSecuredRemoteCacheManager(cacheName, remoteCache.getRemoteCacheManager());
            return securedMgr.getCache(remoteCache.getName());
        } else {
            LOG.info("Remote store security for cache {} is disabled. If server fails to connect to remote JDG server, enable it.", cacheName);
            return remoteCache;
        }
    }


    protected RemoteCacheManager getOrCreateSecuredRemoteCacheManager(String cacheName, RemoteCacheManager origManager) {
        String serverName = this.remoteStoreSecurityServerName;
        String realm = this.remoteStoreSecurityRealm;

        String username = this.remoteStoreSecurityUsername;
        String password = this.remoteStoreSecurityPassword;

        // Create configuration template from the original configuration provided at remoteStore level
        Configuration origConfig = origManager.getConfiguration();

        ConfigurationBuilder cfgBuilder = new ConfigurationBuilder()
                .read(origConfig);

        String securedHotRodEndpoint = origConfig.servers().stream()
                .map(serverConfiguration -> serverConfiguration.host() + ":" + serverConfiguration.port())
                .collect(Collectors.joining(";"));

        if (managedManagers.containsKey(securedHotRodEndpoint)) {
            return managedManagers.get(securedHotRodEndpoint);
        }

        LOG.info("Creating secured RemoteCacheManager for Server: '{}', Cache: '{}', Realm: '{}', Username: '{}', Secured HotRod endpoint: '{}'", serverName, cacheName, realm, username, securedHotRodEndpoint);

        // Workaround as I need a way to override servers and it's not possible to remove existing :/
        try {
            Field serversField = cfgBuilder.getClass().getDeclaredField("servers");
            Reflections.setAccessible(serversField);
            List origServers = Reflections.getFieldValue(serversField, cfgBuilder, List.class);
            origServers.clear();
        } catch (NoSuchFieldException nsfe) {
            throw new RuntimeException(nsfe);
        }

        // Create configuration based on the configuration template from remoteStore. Just add security and override secured endpoint
        Configuration newConfig = cfgBuilder
                .addServers(securedHotRodEndpoint)
                .security()
                .authentication()
                .serverName(serverName) //define server name, should be specified in XML configuration on JDG side
                .saslMechanism("DIGEST-MD5") // define SASL mechanism, in this example we use DIGEST with MD5 hash
                .callbackHandler(new LoginHandler(username, password.toCharArray(), realm)) // define login handler, implementation defined
                .enable()
                .build();

        final RemoteCacheManager remoteCacheManager = new RemoteCacheManager(newConfig);
        managedManagers.put(securedHotRodEndpoint, remoteCacheManager);
        return remoteCacheManager;
    }


    private static class LoginHandler implements CallbackHandler {
        final private String login;
        final private char[] password;
        final private String realm;

        private LoginHandler(String login, char[] password, String realm) {
            this.login = login;
            this.password = password;
            this.realm = realm;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(login);
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password);
                } else if (callback instanceof RealmCallback) {
                    ((RealmCallback) callback).setText(realm);
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    }
}
