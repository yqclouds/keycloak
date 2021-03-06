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
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.common.util.KeyUtils;
import com.hsbc.unified.iam.core.crypto.KeyType;
import com.hsbc.unified.iam.core.crypto.KeyUse;
import com.hsbc.unified.iam.core.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.idm.CertificateRepresentation;
import org.keycloak.services.util.CertificateInfoHelper;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.util.JWKSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientPublicKeyLoader implements PublicKeyLoader {

    private static final Logger LOG = LoggerFactory.getLogger(ClientPublicKeyLoader.class);

    private final ClientModel client;
    private final JWK.Use keyUse;

    @Autowired
    private JWKSHttpUtils jwksHttpUtils;

    public ClientPublicKeyLoader(ClientModel client) {
        this.client = client;
        this.keyUse = JWK.Use.SIG;
    }

    public ClientPublicKeyLoader(ClientModel client, JWK.Use keyUse) {
        this.client = client;
        this.keyUse = keyUse;
    }

    private static KeyWrapper getSignatureValidationKey(CertificateRepresentation certInfo) throws ModelException {
        KeyWrapper keyWrapper = new KeyWrapper();
        String encodedCertificate = certInfo.getCertificate();
        String encodedPublicKey = certInfo.getPublicKey();

        if (encodedCertificate == null && encodedPublicKey == null) {
            throw new ModelException("Client doesn't have certificate or publicKey configured");
        }

        if (encodedCertificate != null && encodedPublicKey != null) {
            throw new ModelException("Client has both publicKey and certificate configured");
        }

        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setType(KeyType.RSA);
        keyWrapper.setUse(KeyUse.SIG);
        String kid = null;
        if (encodedCertificate != null) {
            X509Certificate clientCert = KeycloakModelUtils.getCertificate(encodedCertificate);
            // Check if we have kid in DB, generate otherwise
            kid = certInfo.getKid() != null ? certInfo.getKid() : KeyUtils.createKeyId(clientCert.getPublicKey());
            keyWrapper.setKid(kid);
            keyWrapper.setPublicKey(clientCert.getPublicKey());
            keyWrapper.setCertificate(clientCert);
        } else {
            PublicKey publicKey = KeycloakModelUtils.getPublicKey(encodedPublicKey);
            // Check if we have kid in DB, generate otherwise
            kid = certInfo.getKid() != null ? certInfo.getKid() : KeyUtils.createKeyId(publicKey);
            keyWrapper.setKid(kid);
            keyWrapper.setPublicKey(publicKey);
        }
        return keyWrapper;
    }

    @Autowired
    private ResolveRelative resolveRelative;

    @Override
    public Map<String, KeyWrapper> loadKeys() throws Exception {
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
        if (config.isUseJwksUrl()) {
            String jwksUrl = config.getJwksUrl();
            jwksUrl = resolveRelative.resolveRelativeUri(client.getRootUrl(), jwksUrl);
            JSONWebKeySet jwks = jwksHttpUtils.sendJwksRequest(jwksUrl);
            return JWKSUtils.getKeyWrappersForUse(jwks, keyUse);
        } else if (keyUse == JWK.Use.SIG) {
            try {
                CertificateRepresentation certInfo = CertificateInfoHelper.getCertificateFromClient(client, JWTClientAuthenticator.ATTR_PREFIX);
                KeyWrapper publicKey = getSignatureValidationKey(certInfo);
                return Collections.singletonMap(publicKey.getKid(), publicKey);
            } catch (ModelException me) {
                LOG.warn("Unable to retrieve publicKey for verify signature of client '{}' . Error details: {}", client.getClientId(), me.getMessage());
                return Collections.emptyMap();
            }
        } else {
            LOG.warn("Unable to retrieve publicKey of client '{}' for the specified purpose other than verifying signature", client.getClientId());
            return Collections.emptyMap();
        }
    }
}
