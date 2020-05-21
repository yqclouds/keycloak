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

import com.hsbc.unified.iam.core.crypto.Algorithm;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.util.JWKSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCIdentityProviderPublicKeyLoader implements PublicKeyLoader {

    private static final Logger LOG = LoggerFactory.getLogger(OIDCIdentityProviderPublicKeyLoader.class);

    private final OIDCIdentityProviderConfig config;

    @Autowired
    private JWKSHttpUtils jwksHttpUtils;

    public OIDCIdentityProviderPublicKeyLoader(OIDCIdentityProviderConfig config) {
        this.config = config;
    }

    @Override
    public Map<String, KeyWrapper> loadKeys() throws Exception {
        if (config.isUseJwksUrl()) {
            String jwksUrl = config.getJwksUrl();
            JSONWebKeySet jwks = jwksHttpUtils.sendJwksRequest(jwksUrl);
            return JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG);
        } else {
            try {
                KeyWrapper publicKey = getSavedPublicKey();
                if (publicKey == null) {
                    return Collections.emptyMap();
                }
                return Collections.singletonMap(publicKey.getKid(), publicKey);
            } catch (Exception e) {
                LOG.warn("Unable to retrieve publicKey for verify signature of identityProvider '{}' . Error details: {}", config.getAlias(), e.getMessage());
                return Collections.emptyMap();
            }
        }
    }

    protected KeyWrapper getSavedPublicKey() throws Exception {
        KeyWrapper keyWrapper = null;
        if (config.getPublicKeySignatureVerifier() != null && !config.getPublicKeySignatureVerifier().trim().equals("")) {
            PublicKey publicKey = PemUtils.decodePublicKey(config.getPublicKeySignatureVerifier());
            keyWrapper = new KeyWrapper();
            String presetKeyId = config.getPublicKeySignatureVerifierKeyId();
            String kid = (presetKeyId == null || presetKeyId.trim().isEmpty())
                    ? KeyUtils.createKeyId(publicKey)
                    : presetKeyId;
            keyWrapper.setKid(kid);
            keyWrapper.setType(KeyType.RSA);
            keyWrapper.setAlgorithm(Algorithm.RS256);
            keyWrapper.setUse(KeyUse.SIG);
            keyWrapper.setPublicKey(publicKey);
        } else {
            LOG.warn("No public key saved on identityProvider {}", config.getAlias());
        }
        return keyWrapper;
    }
}
