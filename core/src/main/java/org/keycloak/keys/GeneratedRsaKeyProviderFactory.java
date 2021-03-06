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
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
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
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("GeneratedRsaKeyProviderFactory")
@ProviderFactory(id = "rsa-generated", providerClasses = KeyProvider.class)
public class GeneratedRsaKeyProviderFactory extends AbstractRsaKeyProviderFactory {

    public static final String ID = "rsa-generated";
    private static final Logger LOG = LoggerFactory.getLogger(GeneratedRsaKeyProviderFactory.class);
    private static final String HELP_TEXT = "Generates RSA keys and creates a self-signed certificate";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = AbstractRsaKeyProviderFactory.configurationBuilder()
            .property(Attributes.KEY_SIZE_PROPERTY)
            .build();
    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public KeyProvider create(ComponentModel model) {
        return new ImportedRsaKeyProvider(keycloakContext.getRealm(), model);
    }

    @Override
    public boolean createFallbackKeys(KeyUse keyUse, String algorithm) {
        if (keyUse.equals(KeyUse.SIG) && isSupportedRsaAlgorithm(algorithm)) {
            RealmModel realm = keycloakContext.getRealm();

            ComponentModel generated = new ComponentModel();
            generated.setName("fallback-" + algorithm);
            generated.setParentId(realm.getId());
            generated.setProviderId(ID);
            generated.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Attributes.PRIORITY_KEY, "-100");
            config.putSingle(Attributes.ALGORITHM_KEY, algorithm);
            generated.setConfig(config);

            realm.addComponentModel(generated);

            return true;
        } else {
            return false;
        }
    }

    private boolean isSupportedRsaAlgorithm(String algorithm) {
        return algorithm.equals(Algorithm.RS256)
                || algorithm.equals(Algorithm.PS256)
                || algorithm.equals(Algorithm.RS384)
                || algorithm.equals(Algorithm.PS384)
                || algorithm.equals(Algorithm.RS512)
                || algorithm.equals(Algorithm.PS512);
    }

    @Override
    public void validateConfiguration(RealmModel realm, ComponentModel model) throws ComponentValidationException {
        super.validateConfiguration(realm, model);

        ConfigurationValidationHelper.check(model).checkList(Attributes.KEY_SIZE_PROPERTY, false);

        int size = model.get(Attributes.KEY_SIZE_KEY, 2048);

        if (!(model.contains(Attributes.PRIVATE_KEY_KEY) && model.contains(Attributes.CERTIFICATE_KEY))) {
            generateKeys(realm, model, size);

            LOG.debug("Generated keys for {}", realm.getName());
        } else {
            PrivateKey privateKey = PemUtils.decodePrivateKey(model.get(Attributes.PRIVATE_KEY_KEY));
            int currentSize = ((RSAPrivateKey) privateKey).getModulus().bitLength();
            if (currentSize != size) {
                generateKeys(realm, model, size);

                LOG.debug("Key size changed, generating new keys for {}", realm.getName());
            }
        }
    }

    private void generateKeys(RealmModel realm, ComponentModel model, int size) {
        KeyPair keyPair;
        try {
            keyPair = KeyUtils.generateRsaKeyPair(size);
            model.put(Attributes.PRIVATE_KEY_KEY, PemUtils.encodeKey(keyPair.getPrivate()));
        } catch (Throwable t) {
            throw new ComponentValidationException("Failed to generate keys", t);
        }

        generateCertificate(realm, model, keyPair);
    }

    private void generateCertificate(RealmModel realm, ComponentModel model, KeyPair keyPair) {
        try {
            Certificate certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
            model.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(certificate));
        } catch (Throwable t) {
            throw new ComponentValidationException("Failed to generate certificate", t);
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
