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

package org.keycloak.adapters;

import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.common.util.UriUtils;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Set;

/**
 * Pre-installed actions that must be authenticated
 * <p>
 * Actions include:
 * <p>
 * CORS Origin Check and Response headers
 * k_query_bearer_token: Get bearer token from server for Javascripts CORS requests
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AuthenticatedActionsHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticatedActionsHandler.class);

    protected KeycloakDeployment deployment;
    protected OIDCHttpFacade facade;

    public AuthenticatedActionsHandler(KeycloakDeployment deployment, OIDCHttpFacade facade) {
        this.deployment = deployment;
        this.facade = facade;
    }

    public boolean handledRequest() {
        LOG.debug("AuthenticatedActionsValve.invoke {}", facade.getRequest().getURI());
        if (corsRequest()) return true;
        String requestUri = facade.getRequest().getURI();
        if (requestUri.endsWith(AdapterConstants.K_QUERY_BEARER_TOKEN)) {
            queryBearerToken();
            return true;
        }

        return !isAuthorized();
    }

    protected void queryBearerToken() {
        LOG.debug("queryBearerToken {}", facade.getRequest().getURI());
        if (abortTokenResponse()) return;
        facade.getResponse().setStatus(200);
        facade.getResponse().setHeader("Content-Type", "text/plain");
        try {
            facade.getResponse().getOutputStream().write(facade.getSecurityContext().getTokenString().getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        facade.getResponse().end();
    }

    protected boolean abortTokenResponse() {
        if (facade.getSecurityContext() == null) {
            LOG.debug("Not logged in, sending back 401: {}", facade.getRequest().getURI());
            facade.getResponse().sendError(401);
            facade.getResponse().end();
            return true;
        }
        if (!deployment.isExposeToken()) {
            facade.getResponse().setStatus(200);
            facade.getResponse().end();
            return true;
        }
        // Don't allow a CORS request if we're not validating CORS requests.
        if (!deployment.isCors() && facade.getRequest().getHeader(CorsHeaders.ORIGIN) != null) {
            facade.getResponse().setStatus(200);
            facade.getResponse().end();
            return true;
        }
        return false;
    }

    protected boolean corsRequest() {
        if (!deployment.isCors()) return false;
        KeycloakSecurityContext securityContext = facade.getSecurityContext();
        String origin = facade.getRequest().getHeader(CorsHeaders.ORIGIN);
        String exposeHeaders = deployment.getCorsExposedHeaders();

        if (deployment.getPolicyEnforcer() != null) {
            if (exposeHeaders != null) {
                exposeHeaders += ",";
            } else {
                exposeHeaders = "";
            }

            exposeHeaders += "WWW-Authenticate";
        }

        String requestOrigin = UriUtils.getOrigin(facade.getRequest().getURI());
        LOG.debug("Origin: {} uri: {}", origin, facade.getRequest().getURI());
        if (securityContext != null && origin != null && !origin.equals(requestOrigin)) {
            AccessToken token = securityContext.getToken();
            Set<String> allowedOrigins = token.getAllowedOrigins();

            LOG.debug("Allowed origins in token: {}", allowedOrigins);

            if (allowedOrigins == null || (!allowedOrigins.contains("*") && !allowedOrigins.contains(origin))) {
                if (allowedOrigins == null) {
                    LOG.debug("allowedOrigins was null in token");
                } else {
                    LOG.debug("allowedOrigins did not contain origin");
                }
                facade.getResponse().sendError(403);
                facade.getResponse().end();
                return true;
            }
            LOG.debug("returning origin: {}", origin);
            facade.getResponse().setStatus(200);
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            if (exposeHeaders != null) {
                facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, exposeHeaders);
            }
        } else {
            LOG.debug("cors validation not needed as we are not a secure session or origin header was null: {}", facade.getRequest().getURI());
        }
        return false;
    }

    private boolean isAuthorized() {
        PolicyEnforcer policyEnforcer = this.deployment.getPolicyEnforcer();

        if (policyEnforcer == null) {
            LOG.debug("PolicyModel enforcement is disabled.");
            return true;
        }

        try {
            OIDCHttpFacade facade = this.facade;
            AuthorizationContext authorizationContext = policyEnforcer.enforce(facade);
            RefreshableKeycloakSecurityContext session = (RefreshableKeycloakSecurityContext) facade.getSecurityContext();

            if (session != null) {
                session.setAuthorizationContext(authorizationContext);
            }

            return authorizationContext.isGranted();
        } catch (Exception e) {
            throw new RuntimeException("Failed to enforce policy decisions.", e);
        }
    }
}
