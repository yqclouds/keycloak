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

import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.timer.ScheduledTask;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ClearExpiredUserSessions implements ScheduledTask {

    public static final String TASK_NAME = "ClearExpiredUserSessions";

    @Autowired
    private UserSessionPersisterProvider userSessionPersisterProvider;
    @Autowired
    private UserSessionProvider userSessionProvider;
    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private AuthenticationSessionProvider authenticationSessionProvider;

    @Override
    public void run() {
        for (RealmModel realm : realmProvider.getRealms()) {
            userSessionProvider.removeExpired(realm);
            authenticationSessionProvider.removeExpired(realm);
            userSessionPersisterProvider.removeExpired(realm);
        }
    }
}
