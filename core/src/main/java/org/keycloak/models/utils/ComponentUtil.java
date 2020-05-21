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

package org.keycloak.models.utils;

import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.storage.OnCreateComponent;
import org.keycloak.storage.OnUpdateComponent;
import org.keycloak.storage.UserStorageProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ComponentUtil {

    private static final Logger LOG = LoggerFactory.getLogger(ComponentUtil.class);

    @Autowired
    private UserProvider userProvider;

    public Map<String, ProviderConfigProperty> getComponentConfigProperties(ComponentRepresentation component) {
        return getComponentConfigProperties(component.getProviderType(), component.getProviderId());
    }

    public Map<String, ProviderConfigProperty> getComponentConfigProperties(ComponentModel component) {
        return getComponentConfigProperties(component.getProviderType(), component.getProviderId());
    }

    public ComponentFactory getComponentFactory(ComponentRepresentation component) {
        return getComponentFactory(component.getProviderType(), component.getProviderId());
    }

    public ComponentFactory getComponentFactory(ComponentModel component) {
        return getComponentFactory(component.getProviderType(), component.getProviderId());
    }

    public Map<String, ProviderConfigProperty> getComponentConfigProperties(String providerType, String providerId) {
        try {
            List<ProviderConfigProperty> l = componentFactory.getConfigProperties();
            Map<String, ProviderConfigProperty> properties = new HashMap<>();
            for (ProviderConfigProperty p : l) {
                properties.put(p.getName(), p);
            }
            List<ProviderConfigProperty> common = componentFactory.getCommonProviderConfigProperties();
            for (ProviderConfigProperty p : common) {
                properties.put(p.getName(), p);
            }

            return properties;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Autowired
    private ComponentFactory componentFactory;

    private ComponentFactory getComponentFactory(String providerType, String providerId) {
        return componentFactory;
    }

    public void notifyCreated(RealmModel realm, ComponentModel model) {
        ComponentFactory factory = getComponentFactory(model);
        factory.onCreate(realm, model);
        if (factory instanceof UserStorageProviderFactory) {
            ((OnCreateComponent) userProvider).onCreate(realm, model);
        }
    }

    public void notifyUpdated(RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        ComponentFactory factory = getComponentFactory(newModel);
        factory.onUpdate(realm, oldModel, newModel);
        if (factory instanceof UserStorageProviderFactory) {
            ((OnUpdateComponent) userProvider).onUpdate(realm, oldModel, newModel);
        }
    }

    public void notifyPreRemove(RealmModel realm, ComponentModel model) {
        try {
            ComponentFactory factory = getComponentFactory(model);
            factory.preRemove(realm, model);
        } catch (IllegalArgumentException iae) {
            // We allow to remove broken providers without throwing an exception
            LOG.warn(iae.getMessage());
        }
    }
}
