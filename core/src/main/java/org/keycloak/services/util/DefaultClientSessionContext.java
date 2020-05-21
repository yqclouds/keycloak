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

package org.keycloak.services.util;

import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.util.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Not thread safe. It's per-request object
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientSessionContext implements ClientSessionContext {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultClientSessionContext.class);

    private final AuthenticatedClientSessionModel clientSession;
    private final Set<String> clientScopeIds;

    private Set<ClientScopeModel> clientScopes;

    //
    private Set<RoleModel> roles;
    private Set<ProtocolMapperModel> protocolMappers;

    // All roles of user expanded. It doesn't yet take into account permitted clientScopes
    private Set<RoleModel> userRoles;

    private final Map<String, Object> attributes = new HashMap<>();

    private DefaultClientSessionContext(AuthenticatedClientSessionModel clientSession, Set<String> clientScopeIds) {
        this.clientSession = clientSession;
        this.clientScopeIds = clientScopeIds;
    }


    /**
     * Useful if we want to "re-compute" client scopes based on the scope parameter
     */
    public static DefaultClientSessionContext fromClientSessionScopeParameter(AuthenticatedClientSessionModel clientSession) {
        return fromClientSessionAndScopeParameter(clientSession, clientSession.getNote(OAuth2Constants.SCOPE));
    }


    public static DefaultClientSessionContext fromClientSessionAndScopeParameter(AuthenticatedClientSessionModel clientSession, String scopeParam) {
        Set<ClientScopeModel> requestedClientScopes = TokenManager.getRequestedClientScopes(scopeParam, clientSession.getClient());
        return fromClientSessionAndClientScopes(clientSession, requestedClientScopes);
    }


    public static DefaultClientSessionContext fromClientSessionAndClientScopeIds(AuthenticatedClientSessionModel clientSession, Set<String> clientScopeIds) {
        return new DefaultClientSessionContext(clientSession, clientScopeIds);
    }


    public static DefaultClientSessionContext fromClientSessionAndClientScopes(AuthenticatedClientSessionModel clientSession, Set<ClientScopeModel> clientScopes) {
        Set<String> clientScopeIds = new HashSet<>();
        for (ClientScopeModel clientScope : clientScopes) {
            clientScopeIds.add(clientScope.getId());
        }

        return new DefaultClientSessionContext(clientSession, clientScopeIds);
    }


    @Override
    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }


    @Override
    public Set<String> getClientScopeIds() {
        return clientScopeIds;
    }


    @Override
    public Set<ClientScopeModel> getClientScopes() {
        // Load client scopes if not yet present
        if (clientScopes == null) {
            clientScopes = loadClientScopes();
        }
        return clientScopes;
    }


    @Override
    public Set<RoleModel> getRoles() {
        // Load roles if not yet present
        if (roles == null) {
            roles = loadRoles();
        }
        return roles;
    }


    @Override
    public Set<ProtocolMapperModel> getProtocolMappers() {
        // Load protocolMappers if not yet present
        if (protocolMappers == null) {
            protocolMappers = loadProtocolMappers();
        }
        return protocolMappers;
    }


    private Set<RoleModel> getUserRoles() {
        // Load userRoles if not yet present
        if (userRoles == null) {
            userRoles = loadUserRoles();
        }
        return userRoles;
    }


    @Override
    public String getScopeString() {
        StringBuilder builder = new StringBuilder();

        // Add both default and optional scopes to scope parameter. Don't add client itself
        boolean first = true;
        for (ClientScopeModel clientScope : getClientScopes()) {
            if (clientScope instanceof ClientModel) {
                continue;
            }

            if (!clientScope.isIncludeInTokenScope()) {
                continue;
            }

            if (first) {
                first = false;
            } else {
                builder.append(" ");
            }
            builder.append(clientScope.getName());
        }

        String scopeParam = builder.toString();

        // See if "openid" scope is requested
        String scopeSent = clientSession.getNote(OAuth2Constants.SCOPE);
        if (TokenUtil.isOIDCRequest(scopeSent)) {
            scopeParam = TokenUtil.attachOIDCScope(scopeParam);
        }

        return scopeParam;
    }


    @Override
    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }


    @Override
    public <T> T getAttribute(String name, Class<T> clazz) {
        Object value = attributes.get(name);
        return clazz.cast(value);
    }


    // Loading data

    private Set<ClientScopeModel> loadClientScopes() {
        Set<ClientScopeModel> clientScopes = new HashSet<>();
        for (String scopeId : clientScopeIds) {
            ClientScopeModel clientScope = KeycloakModelUtils.findClientScopeById(clientSession.getClient().getRealm(), getClientSession().getClient(), scopeId);
            if (clientScope != null) {
                if (isClientScopePermittedForUser(clientScope)) {
                    clientScopes.add(clientScope);
                } else {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("User '{}' not permitted to have client scope '{}'",
                                clientSession.getUserSession().getUser().getUsername(), clientScope.getName());
                    }
                }
            }
        }
        return clientScopes;
    }


    // Return true if clientScope can be used by the user.
    private boolean isClientScopePermittedForUser(ClientScopeModel clientScope) {
        if (clientScope instanceof ClientModel) {
            return true;
        }

        Set<RoleModel> clientScopeRoles = clientScope.getScopeMappings();

        // Client scope is automatically permitted if it doesn't have any role scope mappings
        if (clientScopeRoles.isEmpty()) {
            return true;
        }

        // Expand (resolve composite roles)
        clientScopeRoles = RoleUtils.expandCompositeRoles(clientScopeRoles);

        // Check if expanded roles of clientScope has any intersection with expanded roles of user. If not, it is not permitted
        clientScopeRoles.retainAll(getUserRoles());
        return !clientScopeRoles.isEmpty();
    }


    private Set<RoleModel> loadRoles() {
        UserModel user = clientSession.getUserSession().getUser();
        ClientModel client = clientSession.getClient();

        Set<ClientScopeModel> clientScopes = getClientScopes();

        return TokenManager.getAccess(user, client, clientScopes);
    }

    @Autowired
    private ProtocolMapperUtils protocolMapperUtils;

    private Set<ProtocolMapperModel> loadProtocolMappers() {
        Set<ClientScopeModel> clientScopes = getClientScopes();
        String protocol = clientSession.getClient().getProtocol();

        // Being rather defensive. But protocol should normally always be there
        if (protocol == null) {
            LOG.warn("Client '{}' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration", clientSession.getClient().getClientId());
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }

        Set<ProtocolMapperModel> protocolMappers = new HashSet<>();
        for (ClientScopeModel clientScope : clientScopes) {
            Set<ProtocolMapperModel> currentMappers = clientScope.getProtocolMappers();
            for (ProtocolMapperModel currentMapper : currentMappers) {
                if (protocol.equals(currentMapper.getProtocol()) && protocolMapperUtils.isEnabled(currentMapper)) {
                    protocolMappers.add(currentMapper);
                }
            }
        }

        return protocolMappers;
    }


    private Set<RoleModel> loadUserRoles() {
        UserModel user = clientSession.getUserSession().getUser();
        return RoleUtils.getDeepUserRoleMappings(user);
    }

}
