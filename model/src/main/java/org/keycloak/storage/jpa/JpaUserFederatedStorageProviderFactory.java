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
package org.keycloak.storage.jpa;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.storage.federated.UserFederatedStorageProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.persistence.EntityManager;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("JpaUserFederatedStorageProviderFactory")
@ProviderFactory(id = "jpa", providerClasses = UserFederatedStorageProvider.class)
public class JpaUserFederatedStorageProviderFactory implements UserFederatedStorageProviderFactory {
    @Autowired
    private JpaConnectionProvider connectionProvider;

    @Override
    public UserFederatedStorageProvider create(KeycloakSession session) {
        EntityManager em = connectionProvider.getEntityManager();
        return new JpaUserFederatedStorageProvider(session, em);
    }

    @Override
    public String getId() {
        return "jpa";
    }
}
