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

package org.keycloak.keys.loader;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.PublicKey;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PublicKeyStorageManager {
    private static final Logger LOG = LoggerFactory.getLogger(PublicKeyStorageManager.class);

    @Autowired
    private PublicKeyStorageProvider publicKeyStorageProvider;

    public PublicKey getClientPublicKey(ClientModel client, JWSInput input) {
        KeyWrapper keyWrapper = getClientPublicKeyWrapper(client, input);
        PublicKey publicKey = null;
        if (keyWrapper != null) {
            publicKey = (PublicKey) keyWrapper.getPublicKey();
        }
        return publicKey;
    }

    public KeyWrapper getClientPublicKeyWrapper(ClientModel client, JWSInput input) {
        String kid = input.getHeader().getKeyId();
        String modelKey = PublicKeyStorageUtils.getClientModelCacheKey(client.getRealm().getId(), client.getId());
        ClientPublicKeyLoader loader = new ClientPublicKeyLoader(client);
        return publicKeyStorageProvider.getPublicKey(modelKey, kid, loader);
    }


    public KeyWrapper getClientPublicKeyWrapper(ClientModel client, JWK.Use keyUse, String algAlgorithm) {
        String modelKey = PublicKeyStorageUtils.getClientModelCacheKey(client.getRealm().getId(), client.getId(), keyUse);
        ClientPublicKeyLoader loader = new ClientPublicKeyLoader(client, keyUse);
        return publicKeyStorageProvider.getFirstPublicKey(modelKey, algAlgorithm, loader);
    }

    public PublicKey getIdentityProviderPublicKey(RealmModel realm, OIDCIdentityProviderConfig idpConfig, JWSInput input) {
        boolean keyIdSetInConfiguration = idpConfig.getPublicKeySignatureVerifierKeyId() != null
                && !idpConfig.getPublicKeySignatureVerifierKeyId().trim().isEmpty();

        String kid = input.getHeader().getKeyId();

        String modelKey = PublicKeyStorageUtils.getIdpModelCacheKey(realm.getId(), idpConfig.getInternalId());
        PublicKeyLoader loader;
        if (idpConfig.isUseJwksUrl()) {
            loader = new OIDCIdentityProviderPublicKeyLoader(idpConfig);
        } else {
            String pem = idpConfig.getPublicKeySignatureVerifier();

            if (pem == null || pem.trim().isEmpty()) {
                LOG.warn("No public key saved on identityProvider {}", idpConfig.getAlias());
                return null;
            }

            loader = new HardcodedPublicKeyLoader(
                    keyIdSetInConfiguration
                            ? idpConfig.getPublicKeySignatureVerifierKeyId().trim()
                            : kid, pem);
        }

        return (PublicKey) publicKeyStorageProvider.getPublicKey(modelKey, kid, loader).getPublicKey();
    }
}
