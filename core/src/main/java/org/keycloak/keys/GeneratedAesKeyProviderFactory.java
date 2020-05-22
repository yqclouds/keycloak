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

package org.keycloak.keys;

import com.hsbc.unified.iam.core.crypto.Algorithm;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyUse;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("GeneratedAesKeyProviderFactory")
@ProviderFactory(id = "aes-generated", providerClasses = KeyProvider.class)
public class GeneratedAesKeyProviderFactory extends AbstractGeneratedSecretKeyProviderFactory<AbstractGeneratedSecretKeyProvider> {

    public static final String ID = "aes-generated";
    private static final Logger LOG = LoggerFactory.getLogger(GeneratedAesKeyProviderFactory.class);
    private static final String HELP_TEXT = "Generates AES secret key";

    private static final int DEFAULT_AES_KEY_SIZE = 16;

    private static final ProviderConfigProperty AES_KEY_SIZE_PROPERTY;

    static {
        AES_KEY_SIZE_PROPERTY = new ProviderConfigProperty(Attributes.SECRET_SIZE_KEY, "AES Key size",
                "Size in bytes for the generated AES Key. Size 16 is for AES-128, Size 24 for AES-192 and Size 32 for AES-256. WARN: Bigger keys then 128 bits are not allowed on some JDK implementations",
                LIST_TYPE, String.valueOf(DEFAULT_AES_KEY_SIZE), "16", "24", "32");
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = SecretKeyProviderUtils.configurationBuilder()
            .property(AES_KEY_SIZE_PROPERTY)
            .build();

    @Override
    public GeneratedAesKeyProvider create(ComponentModel model) {
        return new GeneratedAesKeyProvider(model);
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public boolean createFallbackKeys(KeyUse keyUse, String algorithm) {
        if (keyUse.equals(KeyUse.ENC) && algorithm.equals(Algorithm.AES)) {
            RealmModel realm = keycloakContext.getRealm();

            ComponentModel generated = new ComponentModel();
            generated.setName("fallback-" + algorithm);
            generated.setParentId(realm.getId());
            generated.setProviderId(ID);
            generated.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Attributes.PRIORITY_KEY, "-100");
            generated.setConfig(config);

            realm.addComponentModel(generated);

            return true;
        } else {
            return false;
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

    @Override
    protected Logger LOG() {
        return LOG;
    }

    @Override
    protected int getDefaultKeySize() {
        return DEFAULT_AES_KEY_SIZE;
    }
}
