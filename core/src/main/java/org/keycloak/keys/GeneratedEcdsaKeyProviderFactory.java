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

import com.hsbc.unified.iam.core.crypto.Algorithm;
import com.hsbc.unified.iam.core.util.Base64;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import com.hsbc.unified.iam.core.crypto.KeyUse;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.util.List;

@Component("GeneratedEcdsaKeyProviderFactory")
@ProviderFactory(id = "ecdsa-generated", providerClasses = KeyProvider.class)
public class GeneratedEcdsaKeyProviderFactory extends AbstractEcdsaKeyProviderFactory {

    public static final String ID = "ecdsa-generated";
    // secp256r1,NIST P-256,X9.62 prime256v1,1.2.840.10045.3.1.7
    public static final String DEFAULT_ECDSA_ELLIPTIC_CURVE = "P-256";
    private static final Logger LOG = LoggerFactory.getLogger(GeneratedEcdsaKeyProviderFactory.class);
    private static final String HELP_TEXT = "Generates ECDSA keys";
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = AbstractEcdsaKeyProviderFactory.configurationBuilder()
            .property(ECDSA_ELLIPTIC_CURVE_PROPERTY)
            .build();

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public KeyProvider create(ComponentModel model) {
        return new GeneratedEcdsaKeyProvider(keycloakContext.getRealm(), model);
    }

    @Override
    public boolean createFallbackKeys(KeyUse keyUse, String algorithm) {
        if (keyUse.equals(KeyUse.SIG) && (algorithm.equals(Algorithm.ES256) || algorithm.equals(Algorithm.ES384) || algorithm.equals(Algorithm.ES512))) {
            RealmModel realm = keycloakContext.getRealm();

            ComponentModel generated = new ComponentModel();
            generated.setName("fallback-" + algorithm);
            generated.setParentId(realm.getId());
            generated.setProviderId(ID);
            generated.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Attributes.PRIORITY_KEY, "-100");
            config.putSingle(ECDSA_ELLIPTIC_CURVE_KEY, convertAlgorithmToECDomainParmNistRep(algorithm));
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
    public void validateConfiguration(RealmModel realm, ComponentModel model) throws ComponentValidationException {
        super.validateConfiguration(realm, model);

        ConfigurationValidationHelper.check(model).checkList(ECDSA_ELLIPTIC_CURVE_PROPERTY, false);

        String ecInNistRep = model.get(ECDSA_ELLIPTIC_CURVE_KEY);
        if (ecInNistRep == null) ecInNistRep = DEFAULT_ECDSA_ELLIPTIC_CURVE;

        if (!(model.contains(ECDSA_PRIVATE_KEY_KEY) && model.contains(ECDSA_PUBLIC_KEY_KEY))) {
            generateKeys(model, ecInNistRep);
            LOG.debug("Generated keys for {}", realm.getName());
        } else {
            String currentEc = model.get(ECDSA_ELLIPTIC_CURVE_KEY);
            if (!ecInNistRep.equals(currentEc)) {
                generateKeys(model, ecInNistRep);
                LOG.debug("Elliptic Curve changed, generating new keys for {}", realm.getName());
            }
        }
    }

    private void generateKeys(ComponentModel model, String ecInNistRep) {
        KeyPair keyPair;
        try {
            keyPair = generateEcdsaKeyPair(convertECDomainParmNistRepToSecRep(ecInNistRep));
            model.put(ECDSA_PRIVATE_KEY_KEY, Base64.encodeBytes(keyPair.getPrivate().getEncoded()));
            model.put(ECDSA_PUBLIC_KEY_KEY, Base64.encodeBytes(keyPair.getPublic().getEncoded()));
            model.put(ECDSA_ELLIPTIC_CURVE_KEY, ecInNistRep);
        } catch (Throwable t) {
            throw new ComponentValidationException("Failed to generate ECDSA keys", t);
        }
    }

}
