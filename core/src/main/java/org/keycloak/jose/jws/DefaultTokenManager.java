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
package org.keycloak.jose.jws;

import com.hsbc.unified.iam.core.crypto.*;
import com.hsbc.unified.iam.core.crypto.Algorithm;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.util.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Map;

public class DefaultTokenManager implements TokenManager {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenManager.class);

    private static String DEFAULT_ALGORITHM_NAME = Algorithm.RS256;

    @Autowired
    private Map<String, SignatureProvider> signatureProviders;
    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public String encode(Token token) {
        String signatureAlgorithm = signatureAlgorithm(token.getCategory());

        SignatureProvider signatureProvider = signatureProviders.get(signatureAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer();

        String encodedToken = new JWSBuilder().type("JWT").jsonContent(token).sign(signer);
        return encodedToken;
    }

    @Autowired
    private KeyManager keyManager;

    @Override
    public <T extends Token> T decode(String token, Class<T> clazz) {
        if (token == null) {
            return null;
        }

        try {
            JWSInput jws = new JWSInput(token);

            String signatureAlgorithm = jws.getHeader().getAlgorithm().name();

            SignatureProvider signatureProvider = signatureProviders.get(signatureAlgorithm);
            if (signatureProvider == null) {
                return null;
            }

            String kid = jws.getHeader().getKeyId();
            // Backwards compatibility. Old offline tokens and cookies didn't have KID in the header
            if (kid == null) {
                LOG.debug("KID is null in token. Using the realm active key to verify token signature.");
                kid = keyManager.getActiveKey(keycloakContext.getRealm(), KeyUse.SIG, signatureAlgorithm).getKid();
            }

            boolean valid = signatureProvider.verifier(kid).verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature());
            return valid ? jws.readJsonContent(clazz) : null;
        } catch (Exception e) {
            LOG.debug("Failed to decode token", e);
            return null;
        }
    }

    @Autowired
    private Map<String, ClientSignatureVerifierProvider> clientSignatureVerifierProviders;

    @Override
    public <T> T decodeClientJWT(String token, ClientModel client, Class<T> clazz) {
        if (token == null) {
            return null;
        }
        try {
            JWSInput jws = new JWSInput(token);

            String signatureAlgorithm = jws.getHeader().getAlgorithm().name();

            ClientSignatureVerifierProvider signatureProvider = clientSignatureVerifierProviders.get(signatureAlgorithm);
            if (signatureProvider == null) {
                return null;
            }

            boolean valid = signatureProvider.verifier(client, jws).verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature());
            return valid ? jws.readJsonContent(clazz) : null;
        } catch (Exception e) {
            LOG.debug("Failed to decode token", e);
            return null;
        }
    }

    @Override
    public String signatureAlgorithm(TokenCategory category) {
        switch (category) {
            case INTERNAL:
                return Algorithm.HS256;
            case ADMIN:
                return getSignatureAlgorithm(null);
            case ACCESS:
                return getSignatureAlgorithm(OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG);
            case ID:
                return getSignatureAlgorithm(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG);
            case USERINFO:
                return getSignatureAlgorithm(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG);
            default:
                throw new RuntimeException("Unknown token type");
        }
    }

    private String getSignatureAlgorithm(String clientAttribute) {
        RealmModel realm = keycloakContext.getRealm();
        ClientModel client = keycloakContext.getClient();

        String algorithm = client != null && clientAttribute != null ? client.getAttribute(clientAttribute) : null;
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }

        algorithm = realm.getDefaultSignatureAlgorithm();
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }

        return DEFAULT_ALGORITHM_NAME;
    }

    @Override
    public String encodeAndEncrypt(Token token) {
        String encodedToken = encode(token);
        if (isTokenEncryptRequired(token.getCategory())) {
            encodedToken = getEncryptedToken(token.getCategory(), encodedToken);
        }
        return encodedToken;
    }

    private boolean isTokenEncryptRequired(TokenCategory category) {
        if (cekManagementAlgorithm(category) == null) return false;
        if (encryptAlgorithm(category) == null) return false;
        return true;
    }

    @Autowired
    private PublicKeyStorageManager publicKeyStorageManager;

    @Autowired
    private Map<String, ContentEncryptionProvider> contentEncryptionProviders;
    @Autowired
    private Map<String, CekManagementProvider> cekManagementProviders;

    private String getEncryptedToken(TokenCategory category, String encodedToken) {
        String encryptedToken = null;

        String algAlgorithm = cekManagementAlgorithm(category);
        String encAlgorithm = encryptAlgorithm(category);

        CekManagementProvider cekManagementProvider = cekManagementProviders.get(algAlgorithm);
        JWEAlgorithmProvider jweAlgorithmProvider = cekManagementProvider.jweAlgorithmProvider();

        ContentEncryptionProvider contentEncryptionProvider = contentEncryptionProviders.get(encAlgorithm);
        JWEEncryptionProvider jweEncryptionProvider = contentEncryptionProvider.jweEncryptionProvider();

        ClientModel client = keycloakContext.getClient();

        KeyWrapper keyWrapper = publicKeyStorageManager.getClientPublicKeyWrapper(client, JWK.Use.ENCRYPTION, algAlgorithm);
        if (keyWrapper == null) {
            throw new RuntimeException("can not get encryption KEK");
        }
        Key encryptionKek = keyWrapper.getPublicKey();
        String encryptionKekId = keyWrapper.getKid();
        try {
            encryptedToken = TokenUtil.jweKeyEncryptionEncode(encryptionKek, encodedToken.getBytes("UTF-8"), algAlgorithm, encAlgorithm, encryptionKekId, jweAlgorithmProvider, jweEncryptionProvider);
        } catch (JWEException | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return encryptedToken;
    }

    @Override
    public String cekManagementAlgorithm(TokenCategory category) {
        if (category == null) return null;
        switch (category) {
            case ID:
                return getCekManagementAlgorithm(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ALG);
            default:
                return null;
        }
    }

    private String getCekManagementAlgorithm(String clientAttribute) {
        ClientModel client = keycloakContext.getClient();
        String algorithm = client != null && clientAttribute != null ? client.getAttribute(clientAttribute) : null;
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }
        return null;
    }

    @Override
    public String encryptAlgorithm(TokenCategory category) {
        if (category == null) return null;
        switch (category) {
            case ID:
                return getEncryptAlgorithm(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ENC);
            default:
                return null;
        }
    }

    private String getEncryptAlgorithm(String clientAttribute) {
        ClientModel client = keycloakContext.getClient();
        String algorithm = client != null && clientAttribute != null ? client.getAttribute(clientAttribute) : null;
        if (algorithm != null && !algorithm.equals("")) {
            return algorithm;
        }
        return null;
    }
}
