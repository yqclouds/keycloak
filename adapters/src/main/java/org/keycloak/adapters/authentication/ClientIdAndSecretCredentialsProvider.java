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

package org.keycloak.adapters.authentication;

import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.util.BasicAuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Traditional OAuth2 authentication of clients based on client_id and client_secret
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientIdAndSecretCredentialsProvider implements ClientCredentialsProvider {
    private static final Logger LOG = LoggerFactory.getLogger(ClientIdAndSecretCredentialsProvider.class);

    public static final String PROVIDER_ID = CredentialRepresentation.SECRET;

    private String clientSecret;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(KeycloakDeployment deployment, Object config) {
        clientSecret = (String) config;
    }

    @Override
    public void setClientCredentials(KeycloakDeployment deployment, Map<String, String> requestHeaders, Map<String, String> formParams) {
        String clientId = deployment.getResourceName();

        if (!deployment.isPublicClient()) {
            if (clientSecret != null) {
                String authorization = BasicAuthHelper.createHeader(clientId, clientSecret);
                requestHeaders.put("Authorization", authorization);
            } else {
                LOG.warn("Client '{}' doesn't have secret available", clientId);
            }
        } else {
            formParams.put(OAuth2Constants.CLIENT_ID, clientId);
        }
    }
}
