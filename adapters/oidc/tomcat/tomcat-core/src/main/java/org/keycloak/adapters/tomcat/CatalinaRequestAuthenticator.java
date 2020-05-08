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

package org.keycloak.adapters.tomcat;

import org.apache.catalina.connector.Request;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.Set;

/**
 * @author <a href="mailto:ungarida@gmail.com">Davide Ungari</a>
 * @version $Revision: 1 $
 */
public class CatalinaRequestAuthenticator extends RequestAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(CatalinaRequestAuthenticator.class);
    protected Request request;
    protected GenericPrincipalFactory principalFactory;

    public CatalinaRequestAuthenticator(KeycloakDeployment deployment,
                                        AdapterTokenStore tokenStore,
                                        CatalinaHttpFacade facade,
                                        Request request,
                                        GenericPrincipalFactory principalFactory) {
        super(facade, deployment, tokenStore, request.getConnector().getRedirectPort());
        this.request = request;
        this.principalFactory = principalFactory;
    }

    @Override
    protected OAuthRequestAuthenticator createOAuthAuthenticator() {
        return new OAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, tokenStore);
    }

    @Override
    protected void completeOAuthAuthentication(final KeycloakPrincipal<RefreshableKeycloakSecurityContext> skp) {
        final RefreshableKeycloakSecurityContext securityContext = skp.getKeycloakSecurityContext();
        final Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);
        OidcKeycloakAccount account = new OidcKeycloakAccount() {

            @Override
            public Principal getPrincipal() {
                return skp;
            }

            @Override
            public Set<String> getRoles() {
                return roles;
            }

            @Override
            public KeycloakSecurityContext getKeycloakSecurityContext() {
                return securityContext;
            }

        };

        request.setAttribute(KeycloakSecurityContext.class.getName(), securityContext);
        this.tokenStore.saveAccountInfo(account);
    }

    @Override
    protected void completeBearerAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method) {
        RefreshableKeycloakSecurityContext securityContext = principal.getKeycloakSecurityContext();
        Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);
        if (LOG.isInfoEnabled()) {
            LOG.info("Completing bearer authentication. Bearer roles: " + roles);
        }
        Principal generalPrincipal = principalFactory.createPrincipal(request.getContext().getRealm(), principal, roles);
        request.setUserPrincipal(generalPrincipal);
        request.setAuthType(method);
        request.setAttribute(KeycloakSecurityContext.class.getName(), securityContext);
    }

    @Override
    protected String changeHttpSessionId(boolean create) {
        HttpSession session = request.getSession(create);
        return session != null ? session.getId() : null;
    }

}
