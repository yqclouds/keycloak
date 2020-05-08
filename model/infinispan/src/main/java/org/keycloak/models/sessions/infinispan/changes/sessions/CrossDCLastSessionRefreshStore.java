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

import org.keycloak.cluster.ClusterProvider;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

/**
 * Cross-DC based CrossDCLastSessionRefreshStore
 * <p>
 * Tracks the queue of lastSessionRefreshes, which were updated on this host. Those will be sent to the second DC in bulk, so second DC can update
 * lastSessionRefreshes on it's side. Message is sent either periodically or if there are lots of stored lastSessionRefreshes.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CrossDCLastSessionRefreshStore extends AbstractLastSessionRefreshStore {

    protected static final Logger LOG = LoggerFactory.getLogger(CrossDCLastSessionRefreshStore.class);

    private final String eventKey;

    @Autowired
    private ClusterProvider clusterProvider;

    protected CrossDCLastSessionRefreshStore(int maxIntervalBetweenMessagesSeconds, int maxCount, String eventKey) {
        super(maxIntervalBetweenMessagesSeconds, maxCount);
        this.eventKey = eventKey;
    }


    protected void sendMessage(KeycloakSession kcSession, Map<String, SessionData> refreshesToSend) {
        LastSessionRefreshEvent event = new LastSessionRefreshEvent(refreshesToSend);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending lastSessionRefreshes for key '{}'. Refreshes: {}", eventKey, event.getLastSessionRefreshes().toString());
        }

        // Don't notify local DC about the lastSessionRefreshes. They were processed here already
        clusterProvider.notify(eventKey, event, true, ClusterProvider.DCNotify.ALL_BUT_LOCAL_DC);
    }
}
