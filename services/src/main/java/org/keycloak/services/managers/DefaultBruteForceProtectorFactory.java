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

package org.keycloak.services.managers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@ProviderFactory(id = "default-brute-force-detector", providerClasses = BruteForceProtector.class)
public class DefaultBruteForceProtectorFactory implements BruteForceProtectorFactory {
    DefaultBruteForceProtector protector;

    @Autowired
    private KeycloakSessionFactory sessionFactory;

    @Override
    public BruteForceProtector create(KeycloakSession session) {
        return protector;
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        protector = new DefaultBruteForceProtector(sessionFactory);
        protector.start();
    }

    @PreDestroy
    public void destroy() throws Exception {
        protector.shutdown();
    }

    @Override
    public String getId() {
        return "default-brute-force-detector";
    }
}
