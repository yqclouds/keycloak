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

package org.keycloak.models.cache.infinispan.authorization;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.cache.authorization.CachedStoreFactoryProvider;
import org.keycloak.models.cache.authorization.CachedStoreProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("InfinispanCacheStoreFactoryProviderFactory")
@ProviderFactory(id = "default", providerClasses = CachedStoreFactoryProvider.class)
public class InfinispanCacheStoreFactoryProviderFactory implements CachedStoreProviderFactory {
    @Override
    public CachedStoreFactoryProvider create(KeycloakSession session) {
        return new StoreFactoryCacheSession(session);
    }

    @Override
    public String getId() {
        return "default";
    }
}
