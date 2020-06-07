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

package org.keycloak.protocol.oidc.installation;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.authorization.admin.AuthorizationService;
import org.keycloak.models.*;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("KeycloakOIDCClientInstallation")
@ProviderFactory(id = "keycloak-oidc-keycloak-json", providerClasses = ClientInstallationProvider.class)
public class KeycloakOIDCClientInstallation implements ClientInstallationProvider {

    @Autowired
    private Map<String, ClientAuthenticatorFactory> clientAuthenticatorFactories;

    public Map<String, Object> getClientCredentialsAdapterConfig(ClientModel client) {
        String clientAuthenticator = client.getClientAuthenticatorType();
        ClientAuthenticatorFactory authenticator = clientAuthenticatorFactories.get(clientAuthenticator);
        return authenticator.getAdapterConfiguration(client);
    }

    public static boolean showClientCredentialsAdapterConfig(ClientModel client) {
        if (client.isPublicClient()) {
            return false;
        }

        return !client.isBearerOnly() || client.isServiceAccountsEnabled() || client.getNodeReRegistrationTimeout() > 0;
    }

    static boolean showVerifyTokenAudience(ClientModel client) {
        // We want to verify-token-audience if service client has any client roles
        if (client.getRoles().size() > 0) {
            return true;
        }

        // Check if there is client scope with audience protocol mapper created for particular client. If yes, admin wants verifying token audience
        String clientId = client.getClientId();

        for (ClientScopeModel clientScope : client.getRealm().getClientScopes()) {
            for (ProtocolMapperModel protocolMapper : clientScope.getProtocolMappers()) {
                if (AudienceProtocolMapper.PROVIDER_ID.equals(protocolMapper.getProtocolMapper()) && (clientId.equals(protocolMapper.getConfig().get(AudienceProtocolMapper.INCLUDED_CLIENT_AUDIENCE)))) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public Response generateInstallation(RealmModel realm, ClientModel client, URI baseUri) {
        ClientManager.InstallationAdapterConfig rep = new ClientManager.InstallationAdapterConfig();
        rep.setAuthServerUrl(baseUri.toString());
        rep.setRealm(realm.getName());
        rep.setSslRequired(realm.getSslRequired().name().toLowerCase());

        if (client.isPublicClient() && !client.isBearerOnly()) rep.setPublicClient(true);
        if (client.isBearerOnly()) rep.setBearerOnly(true);
        if (client.getRoles().size() > 0) rep.setUseResourceRoleMappings(true);

        rep.setResource(client.getClientId());

        if (showClientCredentialsAdapterConfig(client)) {
            Map<String, Object> adapterConfig = getClientCredentialsAdapterConfig(client);
            rep.setCredentials(adapterConfig);
        }

        if (showVerifyTokenAudience(client)) {
            rep.setVerifyTokenAudience(true);
        }

        configureAuthorizationSettings(client, rep);

        String json = null;
        try {
            json = JsonSerialization.writeValueAsPrettyString(rep);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return Response.ok(json, MediaType.TEXT_PLAIN_TYPE).build();
    }

    @Override
    public String getProtocol() {
        return OIDCLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayType() {
        return "Keycloak OIDC JSON";
    }

    @Override
    public String getHelpText() {
        return "keycloak.json file used by the Keycloak OIDC client adapter to configure clients.  This must be saved to a keycloak.json file and put in your WEB-INF directory of your WAR file.  You may also want to tweak this file after you download it.";
    }

    @Override
    public ClientInstallationProvider create() {
        return this;
    }

    @Override
    public String getId() {
        return "keycloak-oidc-keycloak-json";
    }

    @Override
    public boolean isDownloadOnly() {
        return false;
    }

    @Override
    public String getFilename() {
        return "keycloak.json";
    }

    @Override
    public String getMediaType() {
        return MediaType.APPLICATION_JSON;
    }

    private void configureAuthorizationSettings(ClientModel client, ClientManager.InstallationAdapterConfig rep) {
        if (new AuthorizationService(client, null).isEnabled()) {
            PolicyEnforcerConfig enforcerConfig = new PolicyEnforcerConfig();

            enforcerConfig.setEnforcementMode(null);
            enforcerConfig.setLazyLoadPaths(null);

            rep.setEnforcerConfig(enforcerConfig);

            Set<RoleModel> clientRoles = client.getRoles();

            if (clientRoles.size() == 1) {
                if (clientRoles.iterator().next().getName().equals(Constants.AUTHZ_UMA_PROTECTION)) {
                    rep.setUseResourceRoleMappings(null);
                }
            }
        }
    }
}
