/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authentication.authenticators.challenge;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.LoginActionsService;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class NoCookieFlowRedirectAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpRequest httpRequest = context.getHttpRequest();

        // only do redirects for GET requests
        if (HttpMethod.GET.equalsIgnoreCase(httpRequest.getHttpMethod())) {
            KeycloakUriInfo uriInfo = keycloakContext.getUri();
            if (!uriInfo.getQueryParameters().containsKey(LoginActionsService.AUTH_SESSION_ID)) {
                Response response = Response.status(302).header(HttpHeaders.LOCATION, context.getRefreshUrl(true)).build();
                context.challenge(response);
                return;
            }
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }
}

