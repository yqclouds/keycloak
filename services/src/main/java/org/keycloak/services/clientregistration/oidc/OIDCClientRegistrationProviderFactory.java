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

package org.keycloak.services.clientregistration.oidc;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;
import org.keycloak.stereotype.ProviderFactory;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@ProviderFactory(id = "openid-connect", providerClasses = ClientRegistrationProvider.class)
public class OIDCClientRegistrationProviderFactory implements ClientRegistrationProviderFactory {

    public static final String ID = "openid-connect";

    @Override
    public ClientRegistrationProvider create(KeycloakSession session) {
        return new OIDCClientRegistrationProvider(session);
    }

    @Override
    public String getId() {
        return ID;
    }

}
