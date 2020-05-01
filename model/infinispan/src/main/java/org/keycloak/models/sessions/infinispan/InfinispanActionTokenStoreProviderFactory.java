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
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.ActionTokenStoreProvider;
import org.keycloak.models.ActionTokenStoreProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenReducedKey;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenValueEntity;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

/**
 * @author hmlnarik
 */
@ProviderFactory(id = "infinispan")
public class InfinispanActionTokenStoreProviderFactory implements ActionTokenStoreProviderFactory {
    public static final String ACTION_TOKEN_EVENTS = "ACTION_TOKEN_EVENTS";
    private volatile Cache<ActionTokenReducedKey, ActionTokenValueEntity> actionTokenCache;

    @Autowired
    private KeycloakSessionFactory sessionFactory;

    private static Cache<ActionTokenReducedKey, ActionTokenValueEntity> initActionTokenCache(KeycloakSession session) {
        InfinispanConnectionProvider connections = session.getProvider(InfinispanConnectionProvider.class);
        return connections.getCache(InfinispanConnectionProvider.ACTION_TOKEN_CACHE);
    }

    @Override
    public ActionTokenStoreProvider create(KeycloakSession session) {
        return new InfinispanActionTokenStoreProvider(session, this.actionTokenCache);
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        Cache<ActionTokenReducedKey, ActionTokenValueEntity> cache = this.actionTokenCache;

        // It is necessary to put the cache initialization here, otherwise the cache would be initialized lazily, that
        // means also listeners will start only after first cache initialization - that would be too late
        if (cache == null) {
            synchronized (this) {
                cache = this.actionTokenCache;
                if (cache == null) {
                    this.actionTokenCache = initActionTokenCache(sessionFactory.create());
                }
            }
        }
    }
}
