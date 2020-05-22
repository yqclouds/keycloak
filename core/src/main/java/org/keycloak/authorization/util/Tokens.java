/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.util;

import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Tokens {
    @Autowired
    private KeycloakContext context;

    public AccessToken getAccessToken() {
        AppAuthManager authManager = new AppAuthManager();
        AuthResult authResult = authManager.authenticateBearerToken(context.getRealm(), context.getUri(), context.getConnection(), context.getRequestHeaders());

        if (authResult != null) {
            return authResult.getToken();
        }

        return null;
    }

    public AccessToken getAccessToken(String accessToken) {
        AppAuthManager authManager = new AppAuthManager();
        AuthResult authResult = authManager.authenticateBearerToken(accessToken, context.getRealm(), context.getUri(), context.getConnection(), context.getRequestHeaders());

        if (authResult != null) {
            return authResult.getToken();
        }

        return null;
    }

}
