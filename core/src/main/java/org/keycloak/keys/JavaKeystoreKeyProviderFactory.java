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

package org.keycloak.keys;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("JavaKeystoreKeyProviderFactory")
@ProviderFactory(id = "java-keystore", providerClasses = KeyProvider.class)
public class JavaKeystoreKeyProviderFactory extends AbstractRsaKeyProviderFactory {
    public static final String ID = "java-keystore";
    private static final Logger LOG = LoggerFactory.getLogger(JavaKeystoreKeyProviderFactory.class);
    private static final String HELP_TEXT = "Loads keys from a Java keys file";
    public static String KEYSTORE_KEY = "keystore";
    public static ProviderConfigProperty KEYSTORE_PROPERTY = new ProviderConfigProperty(KEYSTORE_KEY, "Keystore", "Path to keys file", STRING_TYPE, null);
    public static String KEYSTORE_PASSWORD_KEY = "keystorePassword";
    public static ProviderConfigProperty KEYSTORE_PASSWORD_PROPERTY = new ProviderConfigProperty(KEYSTORE_PASSWORD_KEY, "Keystore Password", "Password for the keys", STRING_TYPE, null, true);
    public static String KEY_ALIAS_KEY = "keyAlias";
    public static ProviderConfigProperty KEY_ALIAS_PROPERTY = new ProviderConfigProperty(KEY_ALIAS_KEY, "Key Alias", "Alias for the private key", STRING_TYPE, null);
    public static String KEY_PASSWORD_KEY = "keyPassword";
    public static ProviderConfigProperty KEY_PASSWORD_PROPERTY = new ProviderConfigProperty(KEY_PASSWORD_KEY, "Key Password", "Password for the private key", STRING_TYPE, null, true);
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = AbstractRsaKeyProviderFactory.configurationBuilder()
            .property(KEYSTORE_PROPERTY)
            .property(KEYSTORE_PASSWORD_PROPERTY)
            .property(KEY_ALIAS_PROPERTY)
            .property(KEY_PASSWORD_PROPERTY)
            .build();
    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public KeyProvider create(ComponentModel model) {
        return new JavaKeystoreKeyProvider(keycloakContext.getRealm(), model);
    }

    @Override
    public void validateConfiguration(RealmModel realm, ComponentModel model) throws ComponentValidationException {
        super.validateConfiguration(realm, model);

        ConfigurationValidationHelper.check(model)
                .checkSingle(KEYSTORE_PROPERTY, true)
                .checkSingle(KEYSTORE_PASSWORD_PROPERTY, true)
                .checkSingle(KEY_ALIAS_PROPERTY, true)
                .checkSingle(KEY_PASSWORD_PROPERTY, true);

        try {
            new JavaKeystoreKeyProvider(keycloakContext.getRealm(), model)
                    .loadKey(keycloakContext.getRealm(), model);
        } catch (Throwable t) {
            LOG.error("Failed to load keys.", t);
            throw new ComponentValidationException("Failed to load keys. " + t.getMessage(), t);
        }
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return ID;
    }

}
