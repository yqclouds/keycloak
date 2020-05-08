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

package org.keycloak.models.sessions.infinispan;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.commons.api.BasicCache;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseTokenStoreProvider;
import org.keycloak.models.SingleUseTokenStoreProviderFactory;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenValueEntity;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("InfinispanSingleUseTokenStoreProviderFactory")
@ProviderFactory(id = "infinispan", providerClasses = SingleUseTokenStoreProvider.class)
public class InfinispanSingleUseTokenStoreProviderFactory implements SingleUseTokenStoreProviderFactory {
    private static final Logger LOG = LoggerFactory.getLogger(InfinispanSingleUseTokenStoreProviderFactory.class);

    // Reuse "actionTokens" infinispan cache for now
    private volatile Supplier<BasicCache<String, ActionTokenValueEntity>> tokenCache;

    @Autowired
    private InfinispanConnectionProvider connectionProvider;

    @Override
    public InfinispanSingleUseTokenStoreProvider create(KeycloakSession session) {
        lazyInit(session);
        return new InfinispanSingleUseTokenStoreProvider(session, tokenCache);
    }

    private void lazyInit(KeycloakSession session) {
        if (tokenCache == null) {
            synchronized (this) {
                if (tokenCache == null) {
                    Cache cache = connectionProvider.getCache(InfinispanConnectionProvider.ACTION_TOKEN_CACHE);

                    RemoteCache remoteCache = InfinispanUtil.getRemoteCache(cache);

                    if (remoteCache != null) {
                        LOG.debug("Having remote stores. Using remote cache '%s' for single-use cache of token", remoteCache.getName());
                        this.tokenCache = () -> {
                            // Doing this way as flag is per invocation
                            return remoteCache.withFlags(Flag.FORCE_RETURN_VALUE);
                        };
                    } else {
                        LOG.debug("Not having remote stores. Using normal cache '%s' for single-use cache of token", cache.getName());
                        this.tokenCache = () -> {
                            return cache;
                        };
                    }
                }
            }
        }
    }

    @Override
    public String getId() {
        return "infinispan";
    }
}
