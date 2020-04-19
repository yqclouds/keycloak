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
package org.keycloak.services;

import org.keycloak.Config;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.*;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.theme.DefaultThemeManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import javax.annotation.Resource;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class DefaultKeycloakSessionFactory implements KeycloakSessionFactory, ProviderManagerDeployer, InitializingBean {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultKeycloakSessionFactory.class);

    protected CopyOnWriteArrayList<ProviderEventListener> listeners = new CopyOnWriteArrayList<>();
    protected long serverStartupTimestamp;

    private Set<Spi> spis = new HashSet<>();
    private volatile Map<Class<? extends Provider>, Map<String, ProviderFactory>> providerFactories = new HashMap<>();
    private Map<Class<? extends Provider>, String> providers = new HashMap<>();

    private DefaultThemeManagerFactory themeManagerFactory;

    private ProviderManager providerManager;

    public void setSpis(Set<Spi> spis) {
        this.spis = spis;
    }

    @Override
    public void afterPropertiesSet() {
        serverStartupTimestamp = System.currentTimeMillis();

        // spis.addAll(providerManager.loadSpis());
        providerFactories = loadFactories(providerManager);

        synchronized (ProviderManagerRegistry.SINGLETON) {
            for (ProviderManager manager : ProviderManagerRegistry.SINGLETON.getPreBoot()) {
                Map<Class<? extends Provider>, Map<String, ProviderFactory>> factoryMap = loadFactories(manager);
                for (Map.Entry<Class<? extends Provider>, Map<String, ProviderFactory>> entry : factoryMap.entrySet()) {
                    Map<String, ProviderFactory> factories = providerFactories.get(entry.getKey());
                    if (factories == null) {
                        providerFactories.put(entry.getKey(), entry.getValue());
                    } else {
                        factories.putAll(entry.getValue());
                    }
                }
            }
            checkProvider();
            for (Map<String, ProviderFactory> factories : providerFactories.values()) {
                for (ProviderFactory factory : factories.values()) {
                    factory.postInit(this);
                }
            }
            // make the session factory ready for hot deployment
            ProviderManagerRegistry.SINGLETON.setDeployer(this);
        }

        AdminPermissions.registerListener(this);
    }

    @Override
    public void register(ProviderEventListener listener) {
        listeners.add(listener);
    }

    @Override
    public void unregister(ProviderEventListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void publish(ProviderEvent event) {
        for (ProviderEventListener listener : listeners) {
            listener.onEvent(event);
        }
    }

    @Override
    public void deploy(ProviderManager pm) {
        Map<Class<? extends Provider>, Map<String, ProviderFactory>> copy = getFactoriesCopy();
        Map<Class<? extends Provider>, Map<String, ProviderFactory>> newFactories = loadFactories(pm);
        List<ProviderFactory> deployed = new LinkedList<>();
        List<ProviderFactory> undeployed = new LinkedList<>();

        for (Map.Entry<Class<? extends Provider>, Map<String, ProviderFactory>> entry : newFactories.entrySet()) {
            Map<String, ProviderFactory> current = copy.get(entry.getKey());
            if (current == null) {
                copy.put(entry.getKey(), entry.getValue());
            } else {
                for (ProviderFactory f : entry.getValue().values()) {
                    deployed.add(f);
                    ProviderFactory old = current.remove(f.getId());
                    if (old != null) undeployed.add(old);
                }
                current.putAll(entry.getValue());
            }

        }
        providerFactories = copy;
        for (ProviderFactory factory : undeployed) {
            factory.close();
        }
        for (ProviderFactory factory : deployed) {
            factory.postInit(this);
        }

        if (pm.getInfo().hasThemes() || pm.getInfo().hasThemeResources()) {
            themeManagerFactory.clearCache();
        }
    }

    @Override
    public void undeploy(ProviderManager pm) {
        LOG.debug("undeploy");
        // we make a copy to avoid concurrent access exceptions
        Map<Class<? extends Provider>, Map<String, ProviderFactory>> copy = getFactoriesCopy();
        MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> factories = pm.getLoadedFactories();
        List<ProviderFactory> undeployed = new LinkedList<>();
        for (Map.Entry<Class<? extends Provider>, List<ProviderFactory>> entry : factories.entrySet()) {
            Map<String, ProviderFactory> registered = copy.get(entry.getKey());
            for (ProviderFactory factory : entry.getValue()) {
                undeployed.add(factory);
                LOG.debug("undeploying {} of id {}", factory.getClass().getName(), factory.getId());
                if (registered != null) {
                    registered.remove(factory.getId());
                }
            }
        }
        providerFactories = copy;
        for (ProviderFactory factory : undeployed) {
            factory.close();
        }
    }

    protected Map<Class<? extends Provider>, Map<String, ProviderFactory>> getFactoriesCopy() {
        Map<Class<? extends Provider>, Map<String, ProviderFactory>> copy = new HashMap<>();
        for (Map.Entry<Class<? extends Provider>, Map<String, ProviderFactory>> entry : providerFactories.entrySet()) {
            Map<String, ProviderFactory> valCopy = new HashMap<>();
            valCopy.putAll(entry.getValue());
            copy.put(entry.getKey(), valCopy);
        }
        return copy;
    }

    protected DefaultThemeManagerFactory getThemeManagerFactory() {
        return themeManagerFactory;
    }

    protected void checkProvider() {
        for (Spi spi : spis) {
            String provider = Config.getProvider(spi.getName());
            if (provider != null) {
                this.providers.put(spi.getProviderClass(), provider);
                if (getProviderFactory(spi.getProviderClass(), provider) == null) {
                    throw new RuntimeException("Failed to find provider " + provider + " for " + spi.getName());
                }
            } else {
                Map<String, ProviderFactory> factories = providerFactories.get(spi.getProviderClass());
                if (factories != null && factories.size() == 1) {
                    provider = factories.values().iterator().next().getId();
                    this.providers.put(spi.getProviderClass(), provider);
                }
            }
        }
    }

    private boolean isEnabled(ProviderFactory factory, Config.Scope scope) {
        if (!scope.getBoolean("enabled", true)) {
            return false;
        }
        if (factory instanceof EnvironmentDependentProviderFactory) {
            return ((EnvironmentDependentProviderFactory) factory).isSupported();
        }
        return true;
    }

    protected Map<Class<? extends Provider>, Map<String, ProviderFactory>> loadFactories(ProviderManager pm) {
        Map<Class<? extends Provider>, Map<String, ProviderFactory>> factoryMap = new HashMap<>();
        Set<Spi> spiList = spis;

        for (Spi spi : spiList) {

            Map<String, ProviderFactory> factories = new HashMap<>();
            factoryMap.put(spi.getProviderClass(), factories);

            String provider = Config.getProvider(spi.getName());
            if (provider != null) {

                ProviderFactory factory = pm.load(spi, provider);
                if (factory == null) {
                    continue;
                }

                Config.Scope scope = Config.scope(spi.getName(), provider);
                if (isEnabled(factory, scope)) {
                    factory.init(scope);

                    if (spi.isInternal() && !isInternal(factory)) {
                        ServicesLogger.LOGGER.spiMayChange(factory.getId(), factory.getClass().getName(), spi.getName());
                    }

                    factories.put(factory.getId(), factory);

                    LOG.debug("Loaded SPI {} (provider = {})", spi.getName(), provider);
                }

            } else {
                for (ProviderFactory factory : pm.load(spi)) {
                    Config.Scope scope = Config.scope(spi.getName(), factory.getId());
                    if (isEnabled(factory, scope)) {
                        factory.init(scope);

                        if (spi.isInternal() && !isInternal(factory)) {
                            ServicesLogger.LOGGER.spiMayChange(factory.getId(), factory.getClass().getName(), spi.getName());
                        }

                        factories.put(factory.getId(), factory);
                    } else {
                        LOG.debug("SPI {} provider {} disabled", spi.getName(), factory.getId());
                    }
                }
            }
        }
        return factoryMap;
    }

    public KeycloakSession create() {
        return new DefaultKeycloakSession(this);
    }

    <T extends Provider> String getDefaultProvider(Class<T> clazz) {
        return providers.get(clazz);
    }

    @Override
    public Set<Spi> getSpis() {
        return spis;
    }

    @Override
    public Spi getSpi(Class<? extends Provider> providerClass) {
        for (Spi spi : spis) {
            if (spi.getProviderClass().equals(providerClass)) return spi;
        }
        return null;
    }

    @Override
    public <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> clazz) {
        return getProviderFactory(clazz, providers.get(clazz));
    }

    @Override
    public <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> clazz, String id) {
        Map<String, ProviderFactory> map = providerFactories.get(clazz);
        if (map == null) {
            return null;
        }
        return map.get(id);
    }

    @Override
    public List<ProviderFactory> getProviderFactories(Class<? extends Provider> clazz) {
        List<ProviderFactory> list = new LinkedList<>();
        if (providerFactories == null) return list;
        Map<String, ProviderFactory> providerFactoryMap = providerFactories.get(clazz);
        if (providerFactoryMap == null) return list;
        list.addAll(providerFactoryMap.values());
        return list;
    }

    <T extends Provider> Set<String> getAllProviderIds(Class<T> clazz) {
        Set<String> ids = new HashSet<>();
        for (ProviderFactory f : providerFactories.get(clazz).values()) {
            ids.add(f.getId());
        }
        return ids;
    }

    Class<? extends Provider> getProviderClass(String providerClassName) {
        for (Class<? extends Provider> clazz : providerFactories.keySet()) {
            if (clazz.getName().equals(providerClassName)) {
                return clazz;
            }
        }
        return null;
    }

    public void close() {
        ProviderManagerRegistry.SINGLETON.setDeployer(null);
        for (Map<String, ProviderFactory> factories : providerFactories.values()) {
            for (ProviderFactory factory : factories.values()) {
                factory.close();
            }
        }
    }

    private boolean isInternal(ProviderFactory<?> factory) {
        String packageName = factory.getClass().getPackage().getName();
        return packageName.startsWith("org.keycloak") && !packageName.startsWith("org.keycloak.examples");
    }

    /**
     * @return timestamp of Keycloak server startup
     */
    @Override
    public long getServerStartupTimestamp() {
        return serverStartupTimestamp;
    }

    public void setThemeManagerFactory(DefaultThemeManagerFactory themeManagerFactory) {
        this.themeManagerFactory = themeManagerFactory;
    }

    public void setProviderManager(ProviderManager providerManager) {
        this.providerManager = providerManager;
    }
}
