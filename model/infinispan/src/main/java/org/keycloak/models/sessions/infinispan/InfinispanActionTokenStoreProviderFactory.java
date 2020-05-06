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
package org.keycloak.models.sessions.infinispan;

import org.keycloak.models.ActionTokenStoreProvider;
import org.keycloak.models.ActionTokenStoreProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * @author hmlnarik
 */
@Component("InfinispanActionTokenStoreProviderFactory")
@ProviderFactory(id = "infinispan", providerClasses = ActionTokenStoreProvider.class)
public class InfinispanActionTokenStoreProviderFactory implements ActionTokenStoreProviderFactory {
    public static final String ACTION_TOKEN_EVENTS = "ACTION_TOKEN_EVENTS";

    @Override
    public ActionTokenStoreProvider create(KeycloakSession session) {
        return new InfinispanActionTokenStoreProvider(session);
    }
}
