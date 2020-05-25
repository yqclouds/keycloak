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
package org.keycloak.services.resources.admin;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import com.hsbc.unified.iam.web.admin.resources.RealmsResource;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ThemeManager;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.resources.admin.info.ServerInfoAdminResource;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.theme.Theme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.Locale;
import java.util.Properties;

/**
 * Root resource for admin console and admin REST API
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Path("/admin")
public class AdminRoot {
    protected static final Logger LOG = LoggerFactory.getLogger(AdminRoot.class);

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected HttpRequest request;

    @Context
    protected HttpResponse response;

    protected AppAuthManager authManager;
    protected TokenManager tokenManager;

    @Context
    protected KeycloakContext keycloakContext;

    public AdminRoot() {
        this.tokenManager = new TokenManager();
        this.authManager = new AppAuthManager();
    }

    public static UriBuilder adminBaseUrl(UriInfo uriInfo) {
        return adminBaseUrl(uriInfo.getBaseUriBuilder());
    }

    public static UriBuilder adminBaseUrl(UriBuilder base) {
        return base.path(AdminRoot.class);
    }

    public static UriBuilder adminConsoleUrl(UriInfo uriInfo) {
        return adminConsoleUrl(uriInfo.getBaseUriBuilder());
    }

    public static UriBuilder adminConsoleUrl(UriBuilder base) {
        return adminBaseUrl(base).path(AdminRoot.class, "getAdminConsole");
    }

    public static UriBuilder realmsUrl(UriInfo uriInfo) {
        return realmsUrl(uriInfo.getBaseUriBuilder());
    }

    public static UriBuilder realmsUrl(UriBuilder base) {
        return adminBaseUrl(base).path(AdminRoot.class, "getRealmsAdmin");
    }

    @Autowired
    private ThemeManager themeManager;

    public Theme getTheme(RealmModel realm) throws IOException {
        return themeManager.getTheme(Theme.Type.ADMIN);
    }

    public Properties getMessages(RealmModel realm, String lang) {
        try {
            Theme theme = getTheme(realm);
            Locale locale = lang != null ? Locale.forLanguageTag(lang) : Locale.ENGLISH;
            return theme.getMessages(locale);
        } catch (IOException e) {
            LOG.error("Failed to load messages from theme", e);
            return new Properties();
        }
    }

    public Properties getMessages(RealmModel realm, String lang, String... bundles) {
        Properties compound = new Properties();
        for (String bundle : bundles) {
            Properties current = getMessages(realm, lang, bundle);
            compound.putAll(current);
        }
        return compound;
    }

    private Properties getMessages(RealmModel realm, String lang, String bundle) {
        try {
            Theme theme = getTheme(realm);
            Locale locale = lang != null ? Locale.forLanguageTag(lang) : Locale.ENGLISH;
            return theme.getMessages(bundle, locale);
        } catch (IOException e) {
            LOG.error("Failed to load messages from theme", e);
            return new Properties();
        }
    }

    protected AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
        String tokenString = authManager.extractAuthorizationHeaderToken(headers);
        if (tokenString == null) throw new NotAuthorizedException("Bearer");
        AccessToken token;
        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new NotAuthorizedException("Bearer token format error");
        }
        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmFacadeImpl realmFacadeImpl = new RealmFacadeImpl();
        RealmModel realm = realmFacadeImpl.getRealmByName(realmName);
        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
        keycloakContext.setRealm(realm);
        AuthenticationManager.AuthResult authResult = authManager.authenticateBearerToken(realm, keycloakContext.getUri(), clientConnection, headers);
        if (authResult == null) {
            LOG.debug("Token not valid");
            throw new NotAuthorizedException("Bearer");
        }

        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null) {
            throw new NotFoundException("Could not find client for authorization");

        }

        return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
    }

    /**
     * Base Path to realm admin REST interface
     */
    @Path("realms")
    public Object getRealmsAdmin(@Context final HttpHeaders headers) {
        if (request.getHttpMethod().equals(HttpMethod.OPTIONS)) {
            return new AdminCorsPreflightService(request);
        }

        AdminAuth auth = authenticateRealmAdminRequest(headers);
        if (auth != null) {
            LOG.debug("authenticated admin access for: " + auth.getUser().getUsername());
        }

        Cors.add(request).allowedOrigins(auth.getToken()).allowedMethods("GET", "PUT", "POST", "DELETE").exposedHeaders("Location").auth().build(response);

        RealmsResource adminResource = new RealmsResource();
        ResteasyProviderFactory.getInstance().injectProperties(adminResource);
        return adminResource;
    }

    /**
     * General information about the server
     */
    @Path("serverinfo")
    public Object getServerInfo(@Context final HttpHeaders headers) {
        if (request.getHttpMethod().equals(HttpMethod.OPTIONS)) {
            return new AdminCorsPreflightService(request);
        }

        AdminAuth auth = authenticateRealmAdminRequest(headers);
        if (!AdminPermissions.realms(auth).isAdmin()) {
            throw new ForbiddenException();
        }

        if (auth != null) {
            LOG.debug("authenticated admin access for: " + auth.getUser().getUsername());
        }

        Cors.add(request).allowedOrigins(auth.getToken()).allowedMethods("GET", "PUT", "POST", "DELETE").auth().build(response);

        ServerInfoAdminResource adminResource = new ServerInfoAdminResource();
        ResteasyProviderFactory.getInstance().injectProperties(adminResource);
        return adminResource;
    }

}
