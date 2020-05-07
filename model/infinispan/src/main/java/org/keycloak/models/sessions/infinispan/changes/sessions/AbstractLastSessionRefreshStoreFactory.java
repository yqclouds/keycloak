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

package org.keycloak.models.sessions.infinispan.changes.sessions;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.SessionTimeoutHelper;
import org.keycloak.timer.TimerProvider;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractLastSessionRefreshStoreFactory {

    // Timer interval. The store will be checked every 5 seconds whether the message with stored lastSessionRefreshes should be sent
    public static final long DEFAULT_TIMER_INTERVAL_MS = 5000;

    // Max interval between messages. It means that when message is sent to second DC, then another message will be sent at least after 60 seconds.
    public static final int DEFAULT_MAX_INTERVAL_BETWEEN_MESSAGES_SECONDS = SessionTimeoutHelper.PERIODIC_TASK_INTERVAL_SECONDS;

    // Max count of lastSessionRefreshes. If count of lastSessionRefreshes reach this value, the message is sent to second DC
    public static final int DEFAULT_MAX_COUNT = 100;

    @Autowired
    private TimerProvider timerProvider;

    protected void setupPeriodicTimer(AbstractLastSessionRefreshStore store, long timerIntervalMs, String eventKey) {
        timerProvider.scheduleTask((KeycloakSession keycloakSession) -> {
            store.checkSendingMessage(keycloakSession, Time.currentTime());
        }, timerIntervalMs, eventKey);
    }
}
