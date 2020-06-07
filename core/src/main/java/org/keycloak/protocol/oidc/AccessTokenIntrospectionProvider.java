/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.keycloak.protocol.oidc;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import com.hsbc.unified.iam.core.crypto.SignatureProvider;
import com.hsbc.unified.iam.core.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AccessTokenIntrospectionProvider implements TokenIntrospectionProvider {

    private final TokenManager tokenManager;
    private final RealmModel realm;

    @Autowired
    private KeycloakContext context;

    public AccessTokenIntrospectionProvider() {
        this.realm = context.getRealm();
        this.tokenManager = new TokenManager();
    }

    public Response introspect(String token) {
        try {
            AccessToken accessToken = verifyAccessToken(token);
            ObjectNode tokenMetadata;

            if (accessToken != null) {
                tokenMetadata = JsonSerialization.createObjectNode(accessToken);
                tokenMetadata.put("client_id", accessToken.getIssuedFor());
                tokenMetadata.put("username", accessToken.getPreferredUsername());
            } else {
                tokenMetadata = JsonSerialization.createObjectNode();
            }

            tokenMetadata.put("active", accessToken != null);

            return Response.ok(JsonSerialization.writeValueAsBytes(tokenMetadata)).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (Exception e) {
            throw new RuntimeException("Error creating token introspection response.", e);
        }
    }

    @Autowired
    private Map<String, SignatureProvider> signatureProviders;

    protected AccessToken verifyAccessToken(String token) throws OAuthErrorException, IOException {
        AccessToken accessToken;

        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
                    .realmUrl(Urls.realmIssuer(context.getUri().getBaseUri(), realm.getName()));
            SignatureVerifierContext verifierContext = signatureProviders.get(verifier.getHeader().getAlgorithm().name())
                    .verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            accessToken = verifier.verify().getToken();
        } catch (VerificationException e) {
            return null;
        }

        RealmModel realm = context.getRealm();

        return tokenManager.checkTokenValidForIntrospection(realm, accessToken) ? accessToken : null;
    }

    @Override
    public void close() {

    }
}
