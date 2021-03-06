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
import com.hsbc.unified.iam.core.constants.Constants;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import com.hsbc.unified.iam.core.crypto.KeyType;
import com.hsbc.unified.iam.core.crypto.KeyUse;
import com.hsbc.unified.iam.core.crypto.KeyWrapper;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.endpoints.*;
import org.keycloak.protocol.oidc.ext.OIDCExtProvider;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.Cors;
import com.hsbc.unified.iam.web.resources.RealmsResource;
import org.keycloak.services.util.CacheControlUtil;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.LinkedList;
import java.util.List;

/**
 * ResourceModel class for the oauth/openid connect token service
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OIDCLoginProtocolService {

    private RealmModel realm;
    private TokenManager tokenManager;
    private EventBuilder event;

    @Context
    private HttpHeaders headers;

    @Context
    private HttpRequest request;

    @Context
    private ClientConnection clientConnection;

    @Autowired(required = false)
    private OIDCExtProvider oidcExtProvider;

    public OIDCLoginProtocolService(RealmModel realm, EventBuilder event) {
        this.realm = realm;
        this.tokenManager = new TokenManager();
        this.event = event;
    }

    public static UriBuilder tokenServiceBaseUrl(UriInfo uriInfo) {
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return tokenServiceBaseUrl(baseUriBuilder);
    }

    public static UriBuilder tokenServiceBaseUrl(UriBuilder baseUriBuilder) {
        return baseUriBuilder.path(RealmsResource.class).path("{realm}/protocol/" + OIDCLoginProtocol.LOGIN_PROTOCOL);
    }

    public static UriBuilder authUrl(UriInfo uriInfo) {
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return authUrl(baseUriBuilder);
    }

    public static UriBuilder authUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "auth");
    }

    public static UriBuilder tokenUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "token");
    }

    public static UriBuilder certsUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "certs");
    }

    public static UriBuilder userInfoUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "issueUserInfo");
    }

    public static UriBuilder tokenIntrospectionUrl(UriBuilder baseUriBuilder) {
        return tokenUrl(baseUriBuilder).path(TokenEndpoint.class, "introspect");
    }

    public static UriBuilder logoutUrl(UriInfo uriInfo) {
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return logoutUrl(baseUriBuilder);
    }

    public static UriBuilder logoutUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "logout");
    }

    /**
     * Authorization endpoint
     */
    @Path("auth")
    public Object auth() {
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    /**
     * Registration endpoint
     */
    @Path("registrations")
    public Object registerPage() {
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint.register();
    }

    /**
     * Forgot-Credentials endpoint
     */
    @Path("forgot-credentials")
    public Object forgotCredentialsPage() {
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint.forgotCredentials();
    }

    /**
     * Token endpoint
     */
    @Path("token")
    public Object token() {
        TokenEndpoint endpoint = new TokenEndpoint(tokenManager, realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    @Path("login-status-iframe.html")
    public Object getLoginStatusIframe() {
        LoginStatusIframeEndpoint endpoint = new LoginStatusIframeEndpoint();
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    @OPTIONS
    @Path("certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVersionPreflight() {
        return Cors.add(request, Response.ok()).allowedMethods("GET").preflight().auth().build();
    }

    @Autowired
    private KeyManager keyManager;

    @GET
    @Path("certs")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response certs() {
        List<JWK> keys = new LinkedList<>();
        for (KeyWrapper k : keyManager.getKeys(realm)) {
            if (k.getStatus().isEnabled() && k.getUse().equals(KeyUse.SIG) && k.getPublicKey() != null) {
                JWKBuilder b = JWKBuilder.create().kid(k.getKid()).algorithm(k.getAlgorithm());
                if (k.getType().equals(KeyType.RSA)) {
                    keys.add(b.rsa(k.getPublicKey(), k.getCertificate()));
                } else if (k.getType().equals(KeyType.EC)) {
                    keys.add(b.ec(k.getPublicKey()));
                }
            }
        }

        JSONWebKeySet keySet = new JSONWebKeySet();

        JWK[] k = new JWK[keys.size()];
        k = keys.toArray(k);
        keySet.setKeys(k);

        Response.ResponseBuilder responseBuilder = Response.ok(keySet).cacheControl(CacheControlUtil.getDefaultCacheControl());
        return Cors.add(request, responseBuilder).allowedOrigins("*").auth().build();
    }

    @Path("userinfo")
    public Object issueUserInfo() {
        UserInfoEndpoint endpoint = new UserInfoEndpoint(tokenManager, realm);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    @Path("logout")
    public Object logout() {
        LogoutEndpoint endpoint = new LogoutEndpoint(tokenManager, realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;

    @Path("oauth/oob")
    @GET
    public Response installedAppUrnCallback(final @QueryParam("code") String code, final @QueryParam("error") String error, final @QueryParam("error_description") String errorDescription) {
        if (code != null) {
            return loginFormsProvider.setClientSessionCode(code).createCode();
        } else {
            return loginFormsProvider.setError(error).createCode();
        }
    }

    @Autowired
    private KeycloakContext keycloakContext;

    /**
     * For KeycloakInstalled and kcinit login where command line login is delegated to a browser.
     * This clears login cookies and outputs login success or failure messages.
     *
     * @param error
     * @return
     */
    @GET
    @Path("delegated")
    public Response kcinitBrowserLoginComplete(@QueryParam("error") boolean error) {
        AuthenticationManager.expireIdentityCookie(realm, keycloakContext.getUri(), clientConnection);
        AuthenticationManager.expireRememberMeCookie(realm, keycloakContext.getUri(), clientConnection);
        if (error) {
            return loginFormsProvider
                    .setAttribute("messageHeader", loginFormsProvider.getMessage(Messages.DELEGATION_FAILED_HEADER))
                    .setAttribute(Constants.SKIP_LINK, true).setError(Messages.DELEGATION_FAILED).createInfoPage();

        } else {
            return loginFormsProvider
                    .setAttribute("messageHeader", loginFormsProvider.getMessage(Messages.DELEGATION_COMPLETE_HEADER))
                    .setAttribute(Constants.SKIP_LINK, true)
                    .setSuccess(Messages.DELEGATION_COMPLETE).createInfoPage();
        }
    }

    @Path("ext/{extension}")
    public Object resolveExtension(@PathParam("extension") String extension) {
        if (oidcExtProvider != null) {
            oidcExtProvider.setEvent(event);
            return oidcExtProvider;
        }
        throw new NotFoundException();
    }

}
