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

package org.keycloak.protocol.oidc;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import com.hsbc.unified.iam.core.util.Time;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenCategory;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import com.hsbc.unified.iam.core.crypto.HashProvider;
import com.hsbc.unified.iam.core.crypto.SignatureProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.*;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.*;

/**
 * Stateless object that creates tokens and manages oauth access codes
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class TokenManager {
    private static final Logger LOG = LoggerFactory.getLogger(TokenManager.class);
    private static final String JWT = "JWT";

    @Autowired
    private UserSessionProvider userSessionProvider;

    public ClientSessionContext attachAuthenticationSession(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        ClientModel client = authSession.getClient();

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        if (clientSession == null) {
            clientSession = userSessionProvider.createClientSession(userSession.getRealm(), client, userSession);
        }

        clientSession.setRedirectUri(authSession.getRedirectUri());
        clientSession.setProtocol(authSession.getProtocol());

        Set<String> clientScopeIds = authSession.getClientScopes();

        Map<String, String> transferredNotes = authSession.getClientNotes();
        for (Map.Entry<String, String> entry : transferredNotes.entrySet()) {
            clientSession.setNote(entry.getKey(), entry.getValue());
        }

        Map<String, String> transferredUserSessionNotes = authSession.getUserSessionNotes();
        for (Map.Entry<String, String> entry : transferredUserSessionNotes.entrySet()) {
            userSession.setNote(entry.getKey(), entry.getValue());
        }

        clientSession.setTimestamp(Time.currentTime());

        // Remove authentication session now
        new AuthenticationSessionManager().removeAuthenticationSession(userSession.getRealm(), authSession, true);

        return DefaultClientSessionContext.fromClientSessionAndClientScopeIds(clientSession, clientScopeIds);
    }

    public static void dettachClientSession(UserSessionProvider sessions, RealmModel realm, AuthenticatedClientSessionModel clientSession) {
        UserSessionModel userSession = clientSession.getUserSession();
        if (userSession == null) {
            return;
        }

        clientSession.detachFromUserSession();

        // TODO: Might need optimization to prevent loading client sessions from cache in getAuthenticatedClientSessions()
        if (userSession.getAuthenticatedClientSessions().isEmpty()) {
            sessions.removeUserSession(realm, userSession);
        }
    }

    public static Set<RoleModel> getAccess(UserModel user, ClientModel client, Set<ClientScopeModel> clientScopes) {
        Set<RoleModel> roleMappings = RoleUtils.getDeepUserRoleMappings(user);

        if (client.isFullScopeAllowed()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using full scope for client %s", client.getClientId());
            }
            return roleMappings;
        } else {

            // 1 - Client roles of this client itself
            Set<RoleModel> scopeMappings = new HashSet<>(client.getRoles());

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            for (ClientScopeModel clientScope : clientScopes) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Adding client scope role mappings of client scope '%s' to client '%s'", clientScope.getName(), client.getClientId());
                }
                scopeMappings.addAll(clientScope.getScopeMappings());
            }

            // 3 - Expand scope mappings
            scopeMappings = RoleUtils.expandCompositeRoles(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings
            roleMappings.retainAll(scopeMappings);

            return roleMappings;
        }
    }

    /**
     * Return client itself + all default client scopes of client + optional client scopes requested by scope parameter
     **/
    public static Set<ClientScopeModel> getRequestedClientScopes(String scopeParam, ClientModel client) {
        // Add all default client scopes automatically
        Set<ClientScopeModel> clientScopes = new HashSet<>(client.getClientScopes(true, true).values());

        // Add client itself
        clientScopes.add(client);

        if (scopeParam == null) {
            return clientScopes;
        }

        // Add optional client scopes requested by scope parameter
        String[] scopes = scopeParam.split(" ");
        Collection<String> scopeParamParts = Arrays.asList(scopes);
        Map<String, ClientScopeModel> allOptionalScopes = client.getClientScopes(false, true);
        for (String scopeParamPart : scopeParamParts) {
            ClientScopeModel scope = allOptionalScopes.get(scopeParamPart);
            if (scope != null) {
                clientScopes.add(scope);
            }
        }

        return clientScopes;
    }

    @Autowired
    private UserProvider userProvider;

    // Check if user still has granted consents to all requested client scopes
    public boolean verifyConsentStillAvailable(UserModel user, ClientModel client, Set<ClientScopeModel> requestedClientScopes) {
        if (!client.isConsentRequired()) {
            return true;
        }

        UserConsentModel grantedConsent = userProvider.getConsentByClient(client.getRealm(), user.getId(), client.getId());

        for (ClientScopeModel requestedScope : requestedClientScopes) {
            if (!requestedScope.isDisplayOnConsentScreen()) {
                continue;
            }

            if (!grantedConsent.getGrantedClientScopes().contains(requestedScope)) {
                LOG.debug("Client '{}' no longer has requested consent from user '{}' for client scope '{}'",
                        client.getClientId(), user.getUsername(), requestedScope.getName());
                return false;
            }
        }

        return true;
    }

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private KeycloakContext context;

    @Autowired
    private NotBeforeCheck notBeforeCheck;

    public TokenValidation validateToken(UriInfo uriInfo, ClientConnection connection, RealmModel realm,
                                         RefreshToken oldToken, HttpHeaders headers) throws OAuthErrorException {
        UserSessionModel userSession = null;
        boolean offline = TokenUtil.TOKEN_TYPE_OFFLINE.equals(oldToken.getType());

        if (offline) {

            UserSessionManager sessionManager = new UserSessionManager();
            userSession = sessionManager.findOfflineUserSession(realm, oldToken.getSessionState());
            if (userSession != null) {

                // Revoke timeouted offline userSession
                if (!AuthenticationManager.isOfflineSessionValid(realm, userSession)) {
                    sessionManager.revokeOfflineUserSession(userSession);
                    throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Offline session not active", "Offline session not active");
                }

            } else {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Offline user session not found", "Offline user session not found");
            }
        } else {
            // Find userSession regularly for online tokens
            userSession = userSessionProvider.getUserSession(realm, oldToken.getSessionState());
            if (!AuthenticationManager.isSessionValid(realm, userSession)) {
                authenticationManager.backchannelLogout(realm, userSession, uriInfo, connection, headers, true);
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Session not active", "Session not active");
            }
        }

        UserModel user = userSession.getUser();
        if (user == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token", "Unknown user");
        }

        if (!user.isEnabled()) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "User disabled", "User disabled");
        }

        if (oldToken.getIssuedAt() + 1 < userSession.getStarted()) {
            LOG.debug("Refresh toked issued before the user session started");
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Refresh toked issued before the user session started");
        }


        ClientModel client = context.getClient();
        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());

        // Can theoretically happen in cross-dc environment. Try to see if userSession with our client is available in remoteCache
        if (clientSession == null) {
            userSession = new UserSessionCrossDCManager().getUserSessionWithClient(realm, userSession.getId(), offline, client.getId());
            if (userSession != null) {
                clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
            } else {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Session doesn't have required client", "Session doesn't have required client");
            }
        }

        if (!client.getClientId().equals(oldToken.getIssuedFor())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Unmatching clients", "Unmatching clients");
        }

        try {
            TokenVerifier.createWithoutSignature(oldToken)
                    .withChecks(NotBeforeCheck.forModel(client), notBeforeCheck.forModel(realm, user))
                    .verify();
        } catch (VerificationException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Stale token");
        }

        // Setup clientScopes from refresh token to the context
        String oldTokenScope = oldToken.getScope();

        // Case when offline token is migrated from previous version
        if (oldTokenScope == null && userSession.isOffline()) {
            LOG.debug("Migrating offline token of user '{}' for client '{}' of realm '{}'", user.getUsername(), client.getClientId(), realm.getName());
            oldTokenScope = OAuth2Constants.OFFLINE_ACCESS;
        }

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, oldTokenScope);

        // Check user didn't revoke granted consent
        if (!verifyConsentStillAvailable(user, client, clientSessionCtx.getClientScopes())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_SCOPE, "Client no longer has requested consent from user");
        }

        clientSessionCtx.setAttribute(OIDCLoginProtocol.NONCE_PARAM, oldToken.getNonce());

        // recreate token.
        AccessToken newToken = createClientAccessToken(realm, client, user, userSession, clientSessionCtx);

        return new TokenValidation(user, userSession, clientSessionCtx, newToken);
    }

    /**
     * Checks if the token is valid. Intended usage is for token introspection endpoints as the session last refresh
     * is updated if the token was valid. This is used to keep the session alive when long lived tokens are used.
     *
     * @param realm
     * @param token
     * @return
     * @throws OAuthErrorException
     */
    public boolean checkTokenValidForIntrospection(RealmModel realm, AccessToken token) throws OAuthErrorException {
        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null || !client.isEnabled()) {
            return false;
        }

        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(client), TokenVerifier.IS_ACTIVE)
                    .verify();
        } catch (VerificationException e) {
            return false;
        }

        boolean valid = false;

        UserSessionModel userSession = new UserSessionCrossDCManager().getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());

        if (AuthenticationManager.isSessionValid(realm, userSession)) {
            valid = isUserValid(realm, token, userSession);
        } else {
            userSession = new UserSessionCrossDCManager().getUserSessionWithClient(realm, token.getSessionState(), true, client.getId());
            if (AuthenticationManager.isOfflineSessionValid(realm, userSession)) {
                valid = isUserValid(realm, token, userSession);
            }
        }

        if (valid) {
            userSession.setLastSessionRefresh(Time.currentTime());
        }

        return valid;
    }

    private boolean isUserValid(RealmModel realm, AccessToken token, UserSessionModel userSession) {
        UserModel user = userSession.getUser();
        if (user == null) {
            return false;
        }
        if (!user.isEnabled()) {
            return false;
        }
        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(notBeforeCheck.forModel(realm, user))
                    .verify();
        } catch (VerificationException e) {
            return false;
        }

        if (token.getIssuedAt() + 1 < userSession.getStarted()) {
            return false;
        }
        return true;
    }

    public RefreshResult refreshAccessToken(UriInfo uriInfo, ClientConnection connection, RealmModel realm, ClientModel authorizedClient,
                                            String encodedRefreshToken, EventBuilder event, HttpHeaders headers, HttpRequest request) throws OAuthErrorException {
        RefreshToken refreshToken = verifyRefreshToken(realm, authorizedClient, request, encodedRefreshToken, true);

        event.user(refreshToken.getSubject()).session(refreshToken.getSessionState())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.REFRESH_TOKEN_TYPE, refreshToken.getType());

        TokenValidation validation = validateToken(uriInfo, connection, realm, refreshToken, headers);
        AuthenticatedClientSessionModel clientSession = validation.clientSessionCtx.getClientSession();

        // validate authorizedClient is same as validated client
        if (!clientSession.getClient().getId().equals(authorizedClient.getId())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token. Token client and authorized client don't match");
        }

        validateTokenReuse(realm, refreshToken, validation);

        int currentTime = Time.currentTime();
        clientSession.setTimestamp(currentTime);
        validation.userSession.setLastSessionRefresh(currentTime);

        if (refreshToken.getAuthorization() != null) {
            validation.newToken.setAuthorization(refreshToken.getAuthorization());
        }

        AccessTokenResponseBuilder responseBuilder = responseBuilder(realm, authorizedClient, event, validation.userSession, validation.clientSessionCtx)
                .accessToken(validation.newToken)
                .generateRefreshToken();

        if (validation.newToken.getAuthorization() != null) {
            responseBuilder.getRefreshToken().setAuthorization(validation.newToken.getAuthorization());
        }

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3.1
        // bind refreshed access and refresh token with Client Certificate
        AccessToken.CertConf certConf = refreshToken.getCertConf();
        if (certConf != null) {
            responseBuilder.getAccessToken().setCertConf(certConf);
            responseBuilder.getRefreshToken().setCertConf(certConf);
        }

        String scopeParam = clientSession.getNote(OAuth2Constants.SCOPE);
        if (TokenUtil.isOIDCRequest(scopeParam)) {
            responseBuilder.generateIDToken();
        }

        AccessTokenResponse res = responseBuilder.build();

        return new RefreshResult(res, TokenUtil.TOKEN_TYPE_OFFLINE.equals(refreshToken.getType()));
    }

    @Autowired
    private MtlsHoKTokenUtil mtlsHoKTokenUtil;

    private void validateTokenReuse(RealmModel realm, RefreshToken refreshToken,
                                    TokenValidation validation) throws OAuthErrorException {
        if (realm.isRevokeRefreshToken()) {
            AuthenticatedClientSessionModel clientSession = validation.clientSessionCtx.getClientSession();
            if (!refreshToken.getId().equals(clientSession.getCurrentRefreshToken())) {
                clientSession.setCurrentRefreshToken(refreshToken.getId());
                clientSession.setCurrentRefreshTokenUseCount(0);
            }

            int currentCount = clientSession.getCurrentRefreshTokenUseCount();
            if (currentCount > realm.getRefreshTokenMaxReuse()) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Maximum allowed refresh token reuse exceeded",
                        "Maximum allowed refresh token reuse exceeded");
            }
            clientSession.setCurrentRefreshTokenUseCount(currentCount + 1);
        }
    }

    public RefreshToken verifyRefreshToken(RealmModel realm, ClientModel client, HttpRequest request, String encodedRefreshToken, boolean checkExpiration) throws OAuthErrorException {
        try {
            RefreshToken refreshToken = toRefreshToken(encodedRefreshToken);

            if (!(TokenUtil.TOKEN_TYPE_REFRESH.equals(refreshToken.getType()) || TokenUtil.TOKEN_TYPE_OFFLINE.equals(refreshToken.getType()))) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token");
            }

            if (checkExpiration) {
                try {
                    TokenVerifier.createWithoutSignature(refreshToken)
                            .withChecks(NotBeforeCheck.forModel(realm), TokenVerifier.IS_ACTIVE)
                            .verify();
                } catch (VerificationException e) {
                    throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, e.getMessage());
                }
            }

            if (!client.getClientId().equals(refreshToken.getIssuedFor())) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token. Token client and authorized client don't match");
            }

            // KEYCLOAK-6771 Certificate Bound Token
            if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken()) {
                if (!mtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(refreshToken, request)) {
                    throw new OAuthErrorException(OAuthErrorException.UNAUTHORIZED_CLIENT, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
                }
            }

            return refreshToken;
        } catch (JWSInputException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token", e);
        }
    }

    @Autowired
    private org.keycloak.models.TokenManager tokenManager;

    public RefreshToken toRefreshToken(String encodedRefreshToken) throws JWSInputException, OAuthErrorException {
        RefreshToken refreshToken = tokenManager.decode(encodedRefreshToken, RefreshToken.class);
        if (refreshToken == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token");
        }
        return refreshToken;
    }

    public IDToken verifyIDToken(RealmModel realm, String encodedIDToken) throws OAuthErrorException {
        IDToken idToken = tokenManager.decode(encodedIDToken, IDToken.class);
        try {
            TokenVerifier.createWithoutSignature(idToken)
                    .withChecks(NotBeforeCheck.forModel(realm), TokenVerifier.IS_ACTIVE)
                    .verify();
        } catch (VerificationException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, e.getMessage());
        }
        return idToken;
    }

    public IDToken verifyIDTokenSignature(String encodedIDToken) throws OAuthErrorException {
        IDToken idToken = tokenManager.decode(encodedIDToken, IDToken.class);
        if (idToken == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid IDToken");
        }
        return idToken;
    }

    public AccessToken createClientAccessToken(RealmModel realm,
                                               ClientModel client,
                                               UserModel user,
                                               UserSessionModel userSession,
                                               ClientSessionContext clientSessionCtx) {
        AccessToken token = initToken(realm, client, user, userSession, clientSessionCtx, context.getUri());
        token = transformAccessToken(token, userSession, clientSessionCtx);
        return token;
    }

    @Autowired
    private ProtocolMapperUtils protocolMapperUtils;

    public AccessToken transformAccessToken(AccessToken token,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        for (Map.Entry<ProtocolMapperModel, ProtocolMapper> entry : protocolMapperUtils.getSortedProtocolMappers(clientSessionCtx)) {
            ProtocolMapperModel mapping = entry.getKey();
            ProtocolMapper mapper = entry.getValue();
            if (mapper instanceof OIDCAccessTokenMapper) {
                token = ((OIDCAccessTokenMapper) mapper).transformAccessToken(token, mapping, userSession, clientSessionCtx);
            }
        }

        return token;
    }

    public AccessToken transformUserInfoAccessToken(AccessToken token,
                                                    UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        for (Map.Entry<ProtocolMapperModel, ProtocolMapper> entry : protocolMapperUtils.getSortedProtocolMappers(clientSessionCtx)) {
            ProtocolMapperModel mapping = entry.getKey();
            ProtocolMapper mapper = entry.getValue();

            if (mapper instanceof UserInfoTokenMapper) {
                token = ((UserInfoTokenMapper) mapper).transformUserInfoToken(token, mapping, userSession, clientSessionCtx);
            }
        }

        return token;
    }

    public void transformIDToken(IDToken token,
                                 UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        for (Map.Entry<ProtocolMapperModel, ProtocolMapper> entry : protocolMapperUtils.getSortedProtocolMappers(clientSessionCtx)) {
            ProtocolMapperModel mapping = entry.getKey();
            ProtocolMapper mapper = entry.getValue();

            if (mapper instanceof OIDCIDTokenMapper) {
                token = ((OIDCIDTokenMapper) mapper).transformIDToken(token, mapping, userSession, clientSessionCtx);
            }
        }
    }

    protected AccessToken initToken(RealmModel realm, ClientModel client, UserModel user, UserSessionModel session,
                                    ClientSessionContext clientSessionCtx, UriInfo uriInfo) {
        AccessToken token = new AccessToken();
        token.id(KeycloakModelUtils.generateId());
        token.type(TokenUtil.TOKEN_TYPE_BEARER);
        token.subject(user.getId());
        token.issuedNow();
        token.issuedFor(client.getClientId());

        AuthenticatedClientSessionModel clientSession = clientSessionCtx.getClientSession();
        token.issuer(clientSession.getNote(OIDCLoginProtocol.ISSUER));
        token.setNonce(clientSessionCtx.getAttribute(OIDCLoginProtocol.NONCE_PARAM, String.class));
        token.setScope(clientSessionCtx.getScopeString());

        // Best effort for "acr" value. Use 0 if clientSession was authenticated through cookie ( SSO )
        // TODO: Add better acr support. See KEYCLOAK-3314
        String acr = (AuthenticationManager.isSSOAuthentication(clientSession)) ? "0" : "1";
        token.setAcr(acr);

        String authTime = session.getNote(AuthenticationManager.AUTH_TIME);
        if (authTime != null) {
            token.setAuthTime(Integer.parseInt(authTime));
        }


        token.setSessionState(session.getId());
        token.expiration(getTokenExpiration(realm, client, session, clientSession));

        return token;
    }

    private int getTokenExpiration(RealmModel realm, ClientModel client, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        boolean implicitFlow = false;
        String responseType = clientSession.getNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM);
        if (responseType != null) {
            implicitFlow = OIDCResponseType.parse(responseType).isImplicitFlow();
        }

        int tokenLifespan;

        if (implicitFlow) {
            tokenLifespan = realm.getAccessTokenLifespanForImplicitFlow();
        } else {
            String clientLifespan = client.getAttribute(OIDCConfigAttributes.ACCESS_TOKEN_LIFESPAN);
            if (clientLifespan != null && !clientLifespan.trim().isEmpty()) {
                tokenLifespan = Integer.parseInt(clientLifespan);
            } else {
                tokenLifespan = realm.getAccessTokenLifespan();
            }
        }

        int expiration;
        if (tokenLifespan == -1) {
            expiration = userSession.getStarted() + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                    realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan());
        } else {
            expiration = Time.currentTime() + tokenLifespan;
        }

        if (!userSession.isOffline()) {
            int sessionExpires = userSession.getStarted() + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                    realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan());
            expiration = expiration <= sessionExpires ? expiration : sessionExpires;
        }

        return expiration;
    }

    public AccessTokenResponseBuilder responseBuilder(RealmModel realm, ClientModel client, EventBuilder event,
                                                      UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        return new AccessTokenResponseBuilder(realm, client, event, userSession, clientSessionCtx);
    }

    public static class TokenValidation {
        public final UserModel user;
        public final UserSessionModel userSession;
        public final ClientSessionContext clientSessionCtx;
        public final AccessToken newToken;

        public TokenValidation(UserModel user, UserSessionModel userSession, ClientSessionContext clientSessionCtx, AccessToken newToken) {
            this.user = user;
            this.userSession = userSession;
            this.clientSessionCtx = clientSessionCtx;
            this.newToken = newToken;
        }
    }

    public static class NotBeforeCheck implements TokenVerifier.Predicate<JsonWebToken> {

        private final int notBefore;

        public NotBeforeCheck(int notBefore) {
            this.notBefore = notBefore;
        }

        public static NotBeforeCheck forModel(ClientModel clientModel) {
            if (clientModel != null) {

                int notBeforeClient = clientModel.getNotBefore();
                int notBeforeRealm = clientModel.getRealm().getNotBefore();

                int notBefore = (notBeforeClient == 0 ? notBeforeRealm : (notBeforeRealm == 0 ? notBeforeClient :
                        Math.min(notBeforeClient, notBeforeRealm)));

                return new NotBeforeCheck(notBefore);
            }

            return new NotBeforeCheck(0);
        }

        public static NotBeforeCheck forModel(RealmModel realmModel) {
            return new NotBeforeCheck(realmModel == null ? 0 : realmModel.getNotBefore());
        }

        @Autowired
        private UserProvider userProvider;

        public NotBeforeCheck forModel(RealmModel realmModel, UserModel userModel) {
            return new NotBeforeCheck(userProvider.getNotBeforeOfUser(realmModel, userModel));
        }

        @Override
        public boolean test(JsonWebToken t) throws VerificationException {
            if (t.getIssuedAt() < notBefore) {
                throw new VerificationException("Stale token");
            }

            return true;
        }
    }

    public class AccessTokenResponseBuilder {
        RealmModel realm;
        ClientModel client;
        EventBuilder event;
        UserSessionModel userSession;
        ClientSessionContext clientSessionCtx;

        AccessToken accessToken;
        RefreshToken refreshToken;
        IDToken idToken;

        boolean generateAccessTokenHash = false;
        String codeHash;

        String stateHash;

        public AccessTokenResponseBuilder(RealmModel realm,
                                          ClientModel client,
                                          EventBuilder event,
                                          UserSessionModel userSession,
                                          ClientSessionContext clientSessionCtx) {
            this.realm = realm;
            this.client = client;
            this.event = event;
            this.userSession = userSession;
            this.clientSessionCtx = clientSessionCtx;
        }

        public AccessToken getAccessToken() {
            return accessToken;
        }

        public RefreshToken getRefreshToken() {
            return refreshToken;
        }

        public IDToken getIdToken() {
            return idToken;
        }

        public AccessTokenResponseBuilder accessToken(AccessToken accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public AccessTokenResponseBuilder refreshToken(RefreshToken refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public AccessTokenResponseBuilder generateAccessToken() {
            UserModel user = userSession.getUser();
            accessToken = createClientAccessToken(realm, client, user, userSession, clientSessionCtx);
            return this;
        }

        public AccessTokenResponseBuilder generateRefreshToken() {
            if (accessToken == null) {
                throw new IllegalStateException("accessToken not set");
            }

            ClientScopeModel offlineAccessScope = KeycloakModelUtils.getClientScopeByName(realm, OAuth2Constants.OFFLINE_ACCESS);
            boolean offlineTokenRequested = offlineAccessScope != null && clientSessionCtx.getClientScopeIds().contains(offlineAccessScope.getId());
            if (offlineTokenRequested) {
                UserSessionManager sessionManager = new UserSessionManager();
                if (!sessionManager.isOfflineTokenAllowed(clientSessionCtx)) {
                    event.error(Errors.NOT_ALLOWED);
                    throw new ErrorResponseException("not_allowed", "Offline tokens not allowed for the user or client", Response.Status.BAD_REQUEST);
                }

                refreshToken = new RefreshToken(accessToken);
                refreshToken.type(TokenUtil.TOKEN_TYPE_OFFLINE);
                sessionManager.createOrUpdateOfflineSession(clientSessionCtx.getClientSession(), userSession);
            } else {
                refreshToken = new RefreshToken(accessToken);
                refreshToken.expiration(getRefreshExpiration());
            }
            refreshToken.id(KeycloakModelUtils.generateId());
            refreshToken.issuedNow();
            return this;
        }

        private int getRefreshExpiration() {
            int sessionExpires = userSession.getStarted() + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                    realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan());
            int expiration = Time.currentTime() + (userSession.isRememberMe() && realm.getSsoSessionIdleTimeoutRememberMe() > 0 ?
                    realm.getSsoSessionIdleTimeoutRememberMe() : realm.getSsoSessionIdleTimeout());
            return expiration <= sessionExpires ? expiration : sessionExpires;
        }

        public AccessTokenResponseBuilder generateIDToken() {
            if (accessToken == null) {
                throw new IllegalStateException("accessToken not set");
            }
            idToken = new IDToken();
            idToken.id(KeycloakModelUtils.generateId());
            idToken.type(TokenUtil.TOKEN_TYPE_ID);
            idToken.subject(accessToken.getSubject());
            idToken.audience(client.getClientId());
            idToken.issuedNow();
            idToken.issuedFor(accessToken.getIssuedFor());
            idToken.issuer(accessToken.getIssuer());
            idToken.setNonce(accessToken.getNonce());
            idToken.setAuthTime(accessToken.getAuthTime());
            idToken.setSessionState(accessToken.getSessionState());
            idToken.expiration(accessToken.getExpiration());
            idToken.setAcr(accessToken.getAcr());
            transformIDToken(idToken, userSession, clientSessionCtx);
            return this;
        }

        public AccessTokenResponseBuilder generateAccessTokenHash() {
            generateAccessTokenHash = true;
            return this;
        }

        public AccessTokenResponseBuilder generateCodeHash(String code) {
            codeHash = generateOIDCHash(code);
            return this;
        }

        // Financial API - Part 2: Read and Write API Security Profile
        // http://openid.net/specs/openid-financial-api-part-2.html#authorization-server
        public AccessTokenResponseBuilder generateStateHash(String state) {
            stateHash = generateOIDCHash(state);
            return this;
        }

        public AccessTokenResponse build() {
            if (accessToken != null) {
                event.detail(Details.TOKEN_ID, accessToken.getId());
            }

            if (refreshToken != null) {
                if (event.getEvent().getDetails().containsKey(Details.REFRESH_TOKEN_ID)) {
                    event.detail(Details.UPDATED_REFRESH_TOKEN_ID, refreshToken.getId());
                } else {
                    event.detail(Details.REFRESH_TOKEN_ID, refreshToken.getId());
                }
                event.detail(Details.REFRESH_TOKEN_TYPE, refreshToken.getType());
            }

            AccessTokenResponse res = new AccessTokenResponse();

            if (accessToken != null) {
                String encodedToken = tokenManager.encode(accessToken);
                res.setToken(encodedToken);
                res.setTokenType("bearer");
                res.setSessionState(accessToken.getSessionState());
                if (accessToken.getExpiration() != 0) {
                    res.setExpiresIn(accessToken.getExpiration() - Time.currentTime());
                }
            }

            if (generateAccessTokenHash) {
                String atHash = generateOIDCHash(res.getToken());
                idToken.setAccessTokenHash(atHash);
            }
            if (codeHash != null) {
                idToken.setCodeHash(codeHash);
            }
            // Financial API - Part 2: Read and Write API Security Profile
            // http://openid.net/specs/openid-financial-api-part-2.html#authorization-server
            if (stateHash != null) {
                idToken.setStateHash(stateHash);
            }
            if (idToken != null) {
                String encodedToken = tokenManager.encodeAndEncrypt(idToken);
                res.setIdToken(encodedToken);
            }
            if (refreshToken != null) {
                String encodedToken = tokenManager.encode(refreshToken);
                res.setRefreshToken(encodedToken);
                if (refreshToken.getExpiration() != 0) {
                    res.setRefreshExpiresIn(refreshToken.getExpiration() - Time.currentTime());
                }
            }

            int notBefore = realm.getNotBefore();
            if (client.getNotBefore() > notBefore) notBefore = client.getNotBefore();
            int userNotBefore = userProvider.getNotBeforeOfUser(realm, userSession.getUser());
            if (userNotBefore > notBefore) notBefore = userNotBefore;
            res.setNotBeforePolicy(notBefore);

            // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
            String responseScope = clientSessionCtx.getScopeString();
            res.setScope(responseScope);
            event.detail(Details.SCOPE, responseScope);

            return res;
        }

        @Autowired
        private SignatureProvider signatureProvider;
        @Autowired
        private HashProvider hashProvider;

        private String generateOIDCHash(String input) {
            String signatureAlgorithm = tokenManager.signatureAlgorithm(TokenCategory.ID);
            String hashAlgorithm = signatureProvider.signer().getHashAlgorithm();
            byte[] hash = hashProvider.hash(input);

            return HashUtils.encodeHashToOIDC(hash);
        }

    }

    public class RefreshResult {

        private final AccessTokenResponse response;
        private final boolean offlineToken;

        private RefreshResult(AccessTokenResponse response, boolean offlineToken) {
            this.response = response;
            this.offlineToken = offlineToken;
        }

        public AccessTokenResponse getResponse() {
            return response;
        }

        public boolean isOfflineToken() {
            return offlineToken;
        }
    }
}
