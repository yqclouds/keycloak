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

package org.keycloak.authorization;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component("DefaultAuthorizationProviderFactory")
@ProviderFactory(id = "authorization", providerClasses = AuthorizationProvider.class)
public class DefaultAuthorizationProviderFactory implements AuthorizationProviderFactory {
    @Override
    public String getId() {
        return "authorization";
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public AuthorizationProvider create() {
        return create(keycloakContext.getRealm());
    }

    @Override
    public AuthorizationProvider create(RealmModel realm) {
        return new AuthorizationProvider(realm);
    }
}
