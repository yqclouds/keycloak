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

package org.keycloak.authorization.store;

import com.hsbc.unified.iam.entity.events.ClientRemovedEvent;
import com.hsbc.unified.iam.entity.events.GroupRemovedEvent;
import com.hsbc.unified.iam.entity.events.RealmRemovedEvent;
import com.hsbc.unified.iam.entity.events.UserRemovedEvent;
import org.keycloak.authorization.store.syncronization.*;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;
import org.springframework.context.ApplicationEvent;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface AuthorizationStoreFactory extends ProviderFactory<StoreFactory> {

    @Override
    default void postInit(KeycloakSessionFactory factory) {
        registerSynchronizationListeners(factory);
    }

    default void registerSynchronizationListeners(KeycloakSessionFactory factory) {
        Map<Class<? extends ApplicationEvent>, Synchronizer> synchronizers = new HashMap<>();

        synchronizers.put(ClientRemovedEvent.class, new ClientApplicationSynchronizer());
        synchronizers.put(RealmRemovedEvent.class, new RealmSynchronizer());
        synchronizers.put(UserRemovedEvent.class, new UserSynchronizer());
        synchronizers.put(GroupRemovedEvent.class, new GroupSynchronizer());

        factory.register(event -> {
            try {
                synchronizers.forEach((eventType, synchronizer) -> {
                    if (eventType.isInstance(event)) {
                        synchronizer.synchronize(event, factory);
                    }
                });
            } catch (Exception e) {
                throw new RuntimeException("Error synchronizing authorization data.", e);
            }
        });
    }
}
