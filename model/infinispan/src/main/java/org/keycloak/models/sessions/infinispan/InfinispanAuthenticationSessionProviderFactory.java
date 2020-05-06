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

package org.keycloak.models.sessions.infinispan;

import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.sessions.infinispan.events.AbstractAuthSessionClusterListener;
import org.keycloak.models.sessions.infinispan.events.ClientRemovedSessionEvent;
import org.keycloak.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.AuthenticationSessionProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("InfinispanAuthenticationSessionProviderFactory")
@ProviderFactory(id = "infinispan", providerClasses = AuthenticationSessionProvider.class)
@ConditionalOnBean(value = {KeycloakSessionFactory.class})
public class InfinispanAuthenticationSessionProviderFactory implements AuthenticationSessionProviderFactory {
    public static final String PROVIDER_ID = "infinispan";
    public static final String AUTHENTICATION_SESSION_EVENTS = "AUTHENTICATION_SESSION_EVENTS";
    public static final String REALM_REMOVED_AUTHSESSION_EVENT = "REALM_REMOVED_EVENT_AUTHSESSIONS";
    public static final String CLIENT_REMOVED_AUTHSESSION_EVENT = "CLIENT_REMOVED_SESSION_AUTHSESSIONS";
    private static final Logger log = Logger.getLogger(InfinispanAuthenticationSessionProviderFactory.class);

    @Autowired
    private KeycloakSessionFactory sessionFactory;

    @Override
    public AuthenticationSessionProvider create(KeycloakSession session) {
        return new InfinispanAuthenticationSessionProvider();
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        sessionFactory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                KeycloakModelUtils.runJobInTransaction(sessionFactory, this::registerClusterListeners);
            }
        });
    }

    protected void registerClusterListeners(KeycloakSession session) {
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        ClusterProvider cluster = session.getBeanFactory().getBean(ClusterProvider.class);

        cluster.registerListener(REALM_REMOVED_AUTHSESSION_EVENT, new AbstractAuthSessionClusterListener<RealmRemovedSessionEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanAuthenticationSessionProvider provider, RealmRemovedSessionEvent sessionEvent) {
                provider.onRealmRemovedEvent(sessionEvent.getRealmId());
            }
        });

        cluster.registerListener(CLIENT_REMOVED_AUTHSESSION_EVENT, new AbstractAuthSessionClusterListener<ClientRemovedSessionEvent>(sessionFactory) {
            @Override
            protected void eventReceived(KeycloakSession session, InfinispanAuthenticationSessionProvider provider, ClientRemovedSessionEvent sessionEvent) {
                provider.onClientRemovedEvent(sessionEvent.getRealmId(), sessionEvent.getClientUuid());
            }
        });

        log.debug("Registered cluster listeners");
    }

    @Override
    @Deprecated
    public String getId() {
        return PROVIDER_ID;
    }
}
