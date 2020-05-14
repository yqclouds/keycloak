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
package org.keycloak.provider;

import com.hsbc.unified.iam.common.util.MultivaluedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.*;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ProviderManager implements InitializingBean {
    private static final Logger LOG = LoggerFactory.getLogger(ProviderManager.class);

    private final KeycloakDeploymentInfo info;
    private final String[] resources;
    private final ClassLoader baseClassLoader;

    private List<ProviderLoader> loaders = new LinkedList<>();
    private MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> cache = new MultivaluedHashMap<>();

    public ProviderManager(KeycloakDeploymentInfo info, ClassLoader baseClassLoader, String... resources) {
        this.info = info;
        this.baseClassLoader = baseClassLoader;
        this.resources = resources;
    }

    @Override
    public void afterPropertiesSet() {
        List<ProviderLoaderFactory> factories = new LinkedList<>();
        for (ProviderLoaderFactory f : ServiceLoader.load(ProviderLoaderFactory.class, getClass().getClassLoader())) {
            factories.add(f);
        }

        LOG.debug("Provider loaders {}", factories);

        if (resources != null) {
            for (String r : resources) {
                String type = r.substring(0, r.indexOf(':'));
                String resource = r.substring(r.indexOf(':') + 1);

                boolean found = false;
                for (ProviderLoaderFactory f : factories) {
                    if (f.supports(type)) {
                        KeycloakDeploymentInfo resourceInfo = KeycloakDeploymentInfo.create().services();
                        loaders.add(f.create(resourceInfo, baseClassLoader, resource));
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    throw new RuntimeException("Provider loader for " + r + " not found");
                }
            }
        }
    }

    public synchronized List<Spi> loadSpis() {
        // Use a map to prevent duplicates, since the loaders may have overlapping classpaths.
        Map<String, Spi> spiMap = new HashMap<>();
        for (ProviderLoader loader : loaders) {
            List<Spi> spis = loader.loadSpis();
            if (spis != null) {
                for (Spi spi : spis) {
                    spiMap.put(spi.getName(), spi);
                }
            }
        }
        return new LinkedList<>(spiMap.values());
    }

    public synchronized List<ProviderFactory> load(Spi spi) {
        if (!cache.containsKey(spi.getProviderClass())) {

            Set<String> loaded = new HashSet<>();
            for (ProviderLoader loader : loaders) {
                List<ProviderFactory> f = loader.load(spi);
                if (f != null) {
                    for (ProviderFactory pf : f) {
                        String uniqueId = spi.getName() + "-" + pf.getId();
                        if (!loaded.contains(uniqueId)) {
                            cache.add(spi.getProviderClass(), pf);
                            loaded.add(uniqueId);
                        }
                    }
                }
            }
        }
        List<ProviderFactory> rtn = cache.get(spi.getProviderClass());
        return rtn == null ? Collections.EMPTY_LIST : rtn;
    }

    /**
     * returns a copy of internal factories.
     *
     * @return
     */
    public synchronized MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> getLoadedFactories() {
        MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> copy = new MultivaluedHashMap<>();
        copy.addAll(cache);
        return copy;
    }

    public synchronized ProviderFactory load(Spi spi, String providerId) {
        for (ProviderFactory f : load(spi)) {
            if (f.getId().equals(providerId)) {
                return f;
            }
        }
        return null;
    }

    public synchronized KeycloakDeploymentInfo getInfo() {
        return info;
    }

    public void setLoaders(List<ProviderLoader> loaders) {
        this.loaders = loaders;
    }
}
