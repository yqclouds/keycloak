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

package org.keycloak.services.scheduled;

import org.keycloak.events.EventStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.timer.ScheduledTask;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ClearExpiredEvents implements ScheduledTask {

    @Autowired(required = false)
    private EventStoreProvider eventStoreProvider;

    @Override
    public void run(KeycloakSession session) {
        if (eventStoreProvider != null) {
            for (RealmModel realm : session.realms().getRealms()) {
                if (realm.isEventsEnabled() && realm.getEventsExpiration() > 0) {
                    long olderThan = System.currentTimeMillis() - realm.getEventsExpiration() * 1000;
                    eventStoreProvider.clear(realm.getId(), olderThan);
                }
            }
        }
    }

}