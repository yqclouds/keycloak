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

package org.keycloak.storage.ldap;

import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LDAPIdentityStoreRegistry {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPIdentityStoreRegistry.class);

    private Map<String, LDAPIdentityStoreContext> ldapStores = new ConcurrentHashMap<>();

    /**
     * Create LDAPIdentityStore to be cached in the local registry
     */
    public static LDAPIdentityStore createLdapIdentityStore(LDAPConfig cfg) {
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.authentication", cfg.getConnectionPoolingAuthentication(), "none simple");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.initsize", cfg.getConnectionPoolingInitSize(), "1");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.maxsize", cfg.getConnectionPoolingMaxSize(), "1000");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.prefsize", cfg.getConnectionPoolingPrefSize(), "5");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.timeout", cfg.getConnectionPoolingTimeout(), "300000");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.protocol", cfg.getConnectionPoolingProtocol(), "plain");
        checkSystemProperty("com.sun.jndi.ldap.connect.pool.debug", cfg.getConnectionPoolingDebug(), "off");

        return new LDAPIdentityStore(cfg);
    }

    private static void checkSystemProperty(String name, String cfgValue, String defaultValue) {
        String value = System.getProperty(name);
        if (cfgValue != null) {
            value = cfgValue;
        }
        if (value == null) {
            value = defaultValue;
        }
        System.setProperty(name, value);
    }

    public LDAPIdentityStore getLdapStore(ComponentModel ldapModel, Map<ComponentModel, LDAPConfigDecorator> configDecorators) {
        LDAPIdentityStoreContext context = ldapStores.get(ldapModel.getId());

        // Ldap config might have changed for the realm. In this case, we must re-initialize
        MultivaluedHashMap<String, String> configModel = ldapModel.getConfig();
        LDAPConfig ldapConfig = new LDAPConfig(configModel);
        for (Map.Entry<ComponentModel, LDAPConfigDecorator> entry : configDecorators.entrySet()) {
            ComponentModel mapperModel = entry.getKey();
            LDAPConfigDecorator decorator = entry.getValue();

            decorator.updateLDAPConfig(ldapConfig, mapperModel);
        }

        if (context == null || !ldapConfig.equals(context.config)) {
            logLDAPConfig(ldapModel, ldapConfig);

            LDAPIdentityStore store = createLdapIdentityStore(ldapConfig);
            context = new LDAPIdentityStoreContext(ldapConfig, store);
            ldapStores.put(ldapModel.getId(), context);
        }
        return context.store;
    }

    @Autowired
    private RealmProvider realmProvider;

    // Don't log LDAP password
    private void logLDAPConfig(ComponentModel ldapModel, LDAPConfig ldapConfig) {
        LOG.info("Creating new LDAP Store for the LDAP storage provider: '{}', LDAP Configuration: {}", ldapModel.getName(), ldapConfig.toString());

        if (LOG.isDebugEnabled()) {
            RealmModel realm = realmProvider.getRealm(ldapModel.getParentId());
            List<ComponentModel> mappers = realm.getComponents(ldapModel.getId());
            mappers.stream().forEach((ComponentModel c) -> LOG.debug("Mapper for provider: {}, Mapper name: {}, Provider: {}, Mapper configuration: {}", ldapModel.getName(), c.getName(), c.getProviderId(), c.getConfig().toString()));
        }
    }

    private class LDAPIdentityStoreContext {
        private LDAPConfig config;
        private LDAPIdentityStore store;

        private LDAPIdentityStoreContext(LDAPConfig config, LDAPIdentityStore store) {
            this.config = config;
            this.store = store;
        }
    }
}
