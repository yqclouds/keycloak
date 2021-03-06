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

package com.hsbc.unified.iam.web.admin.resources;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hsbc.unified.iam.core.ClientConnection;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RealmClientScopeEvaluateResource {

    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientScopeEvaluateResource.class);

    private final RealmModel realm;
    private final ClientModel client;

    private final UriInfo uriInfo;
    private final ClientConnection clientConnection;

    @Autowired
    private ProtocolMapperUtils protocolMapperUtils;

    public RealmClientScopeEvaluateResource(UriInfo uriInfo,
                                            RealmModel realm,
                                            ClientModel client,
                                            ClientConnection clientConnection) {
        this.uriInfo = uriInfo;
        this.realm = realm;
        this.client = client;
        this.clientConnection = clientConnection;
    }


    /**
     * @param roleContainerId either realm name OR client UUID
     */
    @Path("scope-mappings/{roleContainerId}")
    public RealmClientScopeEvaluateScopeMappingsResource scopeMappings(@QueryParam("scope") String scopeParam, @PathParam("roleContainerId") String roleContainerId) {
        if (roleContainerId == null) {
            throw new NotFoundException("No roleContainerId provided");
        }

        RoleContainerModel roleContainer = roleContainerId.equals(realm.getName()) ? realm : realm.getClientById(roleContainerId);
        if (roleContainer == null) {
            throw new NotFoundException("Role Container not found");
        }

        return new RealmClientScopeEvaluateScopeMappingsResource(roleContainer, client, scopeParam);
    }


    /**
     * Return list of all protocol mappers, which will be used when generating tokens issued for particular client. This means
     * protocol mappers assigned to this client directly and protocol mappers assigned to all client scopes of this client.
     */
    @GET
    @Path("protocol-mappers")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<ProtocolMapperEvaluationRepresentation> getGrantedProtocolMappers(@QueryParam("scope") String scopeParam) {
        List<ProtocolMapperEvaluationRepresentation> protocolMappers = new LinkedList<>();

        Set<ClientScopeModel> clientScopes = TokenManager.getRequestedClientScopes(scopeParam, client);

        for (ClientScopeModel mapperContainer : clientScopes) {
            Set<ProtocolMapperModel> currentMappers = mapperContainer.getProtocolMappers();
            for (ProtocolMapperModel current : currentMappers) {
                if (protocolMapperUtils.isEnabled(current) && current.getProtocol().equals(client.getProtocol())) {
                    ProtocolMapperEvaluationRepresentation rep = new ProtocolMapperEvaluationRepresentation();
                    rep.setMapperId(current.getId());
                    rep.setMapperName(current.getName());
                    rep.setProtocolMapper(current.getProtocolMapper());

                    if (mapperContainer.getId().equals(client.getId())) {
                        // Must be this client
                        rep.setContainerId(client.getId());
                        rep.setContainerName("");
                        rep.setContainerType("client");
                    } else {
                        rep.setContainerId(mapperContainer.getId());
                        rep.setContainerName(mapperContainer.getName());
                        rep.setContainerType("client-scope");
                    }

                    protocolMappers.add(rep);
                }
            }
        }

        return protocolMappers;
    }

    @Autowired
    private UserProvider userProvider;

    /**
     * Create JSON with payload of example access token
     */
    @GET
    @Path("generate-example-access-token")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public AccessToken generateExampleAccessToken(@QueryParam("scope") String scopeParam, @QueryParam("userId") String userId) {
        if (userId == null) {
            throw new NotFoundException("No userId provided");
        }

        UserModel user = userProvider.getUserById(userId, realm);
        if (user == null) {
            throw new NotFoundException("No user found");
        }

        LOG.debug("generateExampleAccessToken invoked. User: {}, ScopeModel param: {}", user.getUsername(), scopeParam);

        return generateToken(user, scopeParam);
    }

    @Autowired
    private TokenManager tokenManager;
    @Autowired
    private UserSessionProvider userSessionProvider;

    private AccessToken generateToken(UserModel user, String scopeParam) {
        AuthenticationSessionModel authSession = null;
        UserSessionModel userSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager();

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setAuthenticatedUser(user);
            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()));
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);

            userSession = userSessionProvider.createUserSession(authSession.getParentSession().getId(), realm, user, user.getUsername(),
                    clientConnection.getRemoteAddr(), "example-auth", false, null, null);

            AuthenticationManager.setClientScopesInSession(authSession);
            ClientSessionContext clientSessionCtx = tokenManager.attachAuthenticationSession(userSession, authSession);

            TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager.responseBuilder(realm, client, null, userSession, clientSessionCtx)
                    .generateAccessToken();

            return responseBuilder.getAccessToken();
        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
            if (userSession != null) {
                userSessionProvider.removeUserSession(realm, userSession);
            }
        }
    }

    public static class ProtocolMapperEvaluationRepresentation {

        @JsonProperty("mapperId")
        private String mapperId;

        @JsonProperty("mapperName")
        private String mapperName;

        @JsonProperty("containerId")
        private String containerId;

        @JsonProperty("containerName")
        private String containerName;

        @JsonProperty("containerType")
        private String containerType;

        @JsonProperty("protocolMapper")
        private String protocolMapper;

        public String getMapperId() {
            return mapperId;
        }

        public void setMapperId(String mapperId) {
            this.mapperId = mapperId;
        }

        public String getMapperName() {
            return mapperName;
        }

        public void setMapperName(String mapperName) {
            this.mapperName = mapperName;
        }

        public String getContainerId() {
            return containerId;
        }

        public void setContainerId(String containerId) {
            this.containerId = containerId;
        }

        public String getContainerName() {
            return containerName;
        }

        public void setContainerName(String containerName) {
            this.containerName = containerName;
        }

        public String getContainerType() {
            return containerType;
        }

        public void setContainerType(String containerType) {
            this.containerType = containerType;
        }

        public String getProtocolMapper() {
            return protocolMapper;
        }

        public void setProtocolMapper(String protocolMapper) {
            this.protocolMapper = protocolMapper;
        }
    }
}
