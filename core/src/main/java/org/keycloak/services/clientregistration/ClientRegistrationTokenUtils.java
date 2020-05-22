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

package org.keycloak.services.clientregistration;

import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.TokenCategory;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.util.TokenUtil;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ClientRegistrationTokenUtils {

    public static final String TYPE_INITIAL_ACCESS_TOKEN = "InitialAccessToken";
    public static final String TYPE_REGISTRATION_ACCESS_TOKEN = "RegistrationAccessToken";

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private TokenManager tokenManager;

    public String updateTokenSignature(ClientRegistrationAuth auth) {
        String algorithm = tokenManager.signatureAlgorithm(TokenCategory.INTERNAL);
        SignatureSignerContext signer = signatureProviders.get(algorithm).signer();

        if (signer.getKid().equals(auth.getKid())) {
            return auth.getToken();
        } else {
            RegistrationAccessToken regToken = new RegistrationAccessToken();
            regToken.setRegistrationAuth(auth.getRegistrationAuth().toString().toLowerCase());

            regToken.type(auth.getJwt().getType());
            regToken.id(auth.getJwt().getId());
            regToken.issuedAt(Time.currentTime());
            regToken.expiration(0);
            regToken.issuer(auth.getJwt().getIssuer());
            regToken.audience(auth.getJwt().getIssuer());

            String token = new JWSBuilder().jsonContent(regToken).sign(signer);
            return token;
        }
    }

    public String updateRegistrationAccessToken(ClientModel client, RegistrationAuth registrationAuth) {
        return updateRegistrationAccessToken(keycloakContext.getRealm(), client, registrationAuth);
    }

    public String updateRegistrationAccessToken(RealmModel realm, ClientModel client, RegistrationAuth registrationAuth) {
        String id = KeycloakModelUtils.generateId();
        client.setRegistrationToken(id);

        RegistrationAccessToken regToken = new RegistrationAccessToken();
        regToken.setRegistrationAuth(registrationAuth.toString().toLowerCase());

        return setupToken(regToken, realm, id, TYPE_REGISTRATION_ACCESS_TOKEN, 0);
    }

    public String createInitialAccessToken(RealmModel realm, ClientInitialAccessModel model) {
        InitialAccessToken initialToken = new InitialAccessToken();
        return setupToken(initialToken, realm, model.getId(), TYPE_INITIAL_ACCESS_TOKEN, model.getExpiration() > 0 ? model.getTimestamp() + model.getExpiration() : 0);
    }

    @Autowired
    private Map<String, SignatureProvider> signatureProviders;

    public TokenVerification verifyToken(RealmModel realm, String token) {
        if (token == null) {
            return TokenVerification.error(new RuntimeException("Missing token"));
        }

        String kid;
        JsonWebToken jwt;
        try {
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(token, JsonWebToken.class)
                    .withChecks(new TokenVerifier.RealmUrlCheck(getIssuer(realm)), TokenVerifier.IS_ACTIVE);

            SignatureVerifierContext verifierContext = signatureProviders.get(verifier.getHeader().getAlgorithm().name())
                    .verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            kid = verifierContext.getKid();

            verifier.verify();

            jwt = verifier.getToken();
        } catch (VerificationException e) {
            return TokenVerification.error(new RuntimeException("Failed decode token", e));
        }

        if (!(TokenUtil.TOKEN_TYPE_BEARER.equals(jwt.getType()) ||
                TYPE_INITIAL_ACCESS_TOKEN.equals(jwt.getType()) ||
                TYPE_REGISTRATION_ACCESS_TOKEN.equals(jwt.getType()))) {
            return TokenVerification.error(new RuntimeException("Invalid type of token"));
        }

        return TokenVerification.success(kid, jwt);
    }

    private String setupToken(JsonWebToken jwt, RealmModel realm, String id, String type, int expiration) {
        String issuer = getIssuer(realm);

        jwt.type(type);
        jwt.id(id);
        jwt.issuedAt(Time.currentTime());
        jwt.expiration(expiration);
        jwt.issuer(issuer);
        jwt.audience(issuer);

        return tokenManager.encode(jwt);
    }

    private String getIssuer(RealmModel realm) {
        return Urls.realmIssuer(keycloakContext.getUri().getBaseUri(), realm.getName());
    }

    protected static class TokenVerification {

        private final String kid;
        private final JsonWebToken jwt;
        private final RuntimeException error;

        private TokenVerification(String kid, JsonWebToken jwt, RuntimeException error) {
            this.kid = kid;
            this.jwt = jwt;
            this.error = error;
        }

        public static TokenVerification success(String kid, JsonWebToken jwt) {
            return new TokenVerification(kid, jwt, null);
        }

        public static TokenVerification error(RuntimeException error) {
            return new TokenVerification(null, null, error);
        }

        public String getKid() {
            return kid;
        }

        public JsonWebToken getJwt() {
            return jwt;
        }

        public RuntimeException getError() {
            return error;
        }
    }

}
