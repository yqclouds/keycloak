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

package org.keycloak.protocol.oidc.mappers;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.WebOriginsUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.stereotype.ProviderFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Protocol mapper to add allowed web origins to the access token to the 'allowed-origins' claim
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@ProviderFactory(id = "oidc-allowed-origins-mapper")
public class AllowedWebOriginsProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-allowed-origins-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static ProtocolMapperModel createClaimMapper(String name) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        mapper.setConfig(Collections.emptyMap());
        return mapper;
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Allowed Web Origins";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Adds all allowed web origins to the 'allowed-origins' claim in the token";
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        ClientModel client = clientSessionCtx.getClientSession().getClient();

        Set<String> allowedOrigins = client.getWebOrigins();
        if (allowedOrigins != null && !allowedOrigins.isEmpty()) {
            token.setAllowedOrigins(WebOriginsUtils.resolveValidWebOrigins(session, client));
        }

        return token;
    }

}
