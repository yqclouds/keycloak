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

package org.keycloak.events.jpa;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.events.EventModel;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEventModel;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class JpaEventStoreProvider implements EventStoreProvider {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final TypeReference<Map<String, String>> mapType = new TypeReference<Map<String, String>>() {
    };
    private static final Logger LOG = LoggerFactory.getLogger(JpaEventStoreProvider.class);

    private final int maxDetailLength;

    @Autowired
    private EventRepository eventRepository;
    @Autowired
    private AdminEventRepository adminEventRepository;

    public JpaEventStoreProvider(int maxDetailLength) {
        this.maxDetailLength = maxDetailLength;
    }

    static EventModel convertEvent(Event eventEntity) {
        EventModel event = new EventModel();
        event.setTime(eventEntity.getTime());
        event.setType(EventType.valueOf(eventEntity.getType()));
        event.setRealmId(eventEntity.getRealmId());
        event.setClientId(eventEntity.getClientId());
        event.setUserId(eventEntity.getUserId());
        event.setSessionId(eventEntity.getSessionId());
        event.setIpAddress(eventEntity.getIpAddress());
        event.setError(eventEntity.getError());
        try {
            Map<String, String> details = mapper.readValue(eventEntity.getDetailsJson(), mapType);
            event.setDetails(details);
        } catch (IOException ex) {
            LOG.error("Failed to read log details", ex);
        }
        return event;
    }

    static AdminEvent convertAdminEvent(AdminEventModel adminEvent, boolean includeRepresentation) {
        AdminEvent adminEventEntity = new AdminEvent();
        adminEventEntity.setId(UUID.randomUUID().toString());
        adminEventEntity.setTime(adminEvent.getTime());
        adminEventEntity.setRealmId(adminEvent.getRealmId());
        setAuthDetails(adminEventEntity, adminEvent.getAuthDetails());
        adminEventEntity.setOperationType(adminEvent.getOperationType().toString());

        if (adminEvent.getResourceTypeAsString() != null) {
            adminEventEntity.setResourceType(adminEvent.getResourceTypeAsString());
        }

        adminEventEntity.setResourcePath(adminEvent.getResourcePath());
        adminEventEntity.setError(adminEvent.getError());

        if (includeRepresentation) {
            adminEventEntity.setRepresentation(adminEvent.getRepresentation());
        }
        return adminEventEntity;
    }

    static AdminEventModel convertAdminEvent(AdminEvent adminEventEntity) {
        AdminEventModel adminEvent = new AdminEventModel();
        adminEvent.setTime(adminEventEntity.getTime());
        adminEvent.setRealmId(adminEventEntity.getRealmId());
        setAuthDetails(adminEvent, adminEventEntity);
        adminEvent.setOperationType(OperationType.valueOf(adminEventEntity.getOperationType()));

        if (adminEventEntity.getResourceType() != null) {
            adminEvent.setResourceTypeAsString(adminEventEntity.getResourceType());
        }

        adminEvent.setResourcePath(adminEventEntity.getResourcePath());
        adminEvent.setError(adminEventEntity.getError());

        if (adminEventEntity.getRepresentation() != null) {
            adminEvent.setRepresentation(adminEventEntity.getRepresentation());
        }
        return adminEvent;
    }

    private static void setAuthDetails(AdminEvent adminEventEntity, AuthDetails authDetails) {
        adminEventEntity.setAuthRealmId(authDetails.getRealmId());
        adminEventEntity.setAuthClientId(authDetails.getClientId());
        adminEventEntity.setAuthUserId(authDetails.getUserId());
        adminEventEntity.setAuthIpAddress(authDetails.getIpAddress());
    }

    private static void setAuthDetails(AdminEventModel adminEvent, AdminEvent adminEventEntity) {
        AuthDetails authDetails = new AuthDetails();
        authDetails.setRealmId(adminEventEntity.getAuthRealmId());
        authDetails.setClientId(adminEventEntity.getAuthClientId());
        authDetails.setUserId(adminEventEntity.getAuthUserId());
        authDetails.setIpAddress(adminEventEntity.getAuthIpAddress());
        adminEvent.setAuthDetails(authDetails);
    }

    @Override
    public EventQuery createQuery() {
        return new JpaEventQuery();
    }

    @Override
    public void clear() {
        eventRepository.deleteAll();
    }

    @Override
    public void clear(String realmId) {
        eventRepository.deleteByRealmId(realmId);
    }

    @Override
    public void clear(String realmId, long olderThan) {
        eventRepository.deleteByRealmIdAndTimeLessThan(realmId, olderThan);
    }

    @Override
    public void onEvent(EventModel event) {
        eventRepository.save(convertEvent(event));
    }

    @Override
    public AdminEventQuery createAdminQuery() {
        return new JpaAdminEventQuery();
    }

    @Override
    public void clearAdmin() {
        adminEventRepository.deleteAll();
    }

    @Override
    public void clearAdmin(String realmId) {
        adminEventRepository.deleteByRealmId(realmId);
    }

    @Override
    public void clearAdmin(String realmId, long olderThan) {
        adminEventRepository.deleteByRealmIdAndTimeLessThan(realmId, olderThan);
    }

    @Override
    public void onEvent(AdminEventModel event, boolean includeRepresentation) {
        adminEventRepository.save(convertAdminEvent(event, includeRepresentation));
    }

    @Override
    public void close() {
    }

    private Event convertEvent(EventModel event) {
        Event eventEntity = new Event();
        eventEntity.setId(UUID.randomUUID().toString());
        eventEntity.setTime(event.getTime());
        eventEntity.setType(event.getType().toString());
        eventEntity.setRealmId(event.getRealmId());
        eventEntity.setClientId(event.getClientId());
        eventEntity.setUserId(event.getUserId());
        eventEntity.setSessionId(event.getSessionId());
        eventEntity.setIpAddress(event.getIpAddress());
        eventEntity.setError(event.getError());
        try {
            if (maxDetailLength > 0 && event.getDetails() != null) {
                Map<String, String> result = new HashMap<>(event.getDetails());
                result.entrySet().forEach(t -> t.setValue(trimToMaxLength(t.getValue())));

                eventEntity.setDetailsJson(mapper.writeValueAsString(result));
            } else {
                eventEntity.setDetailsJson(mapper.writeValueAsString(event.getDetails()));
            }
        } catch (IOException ex) {
            LOG.error("Failed to write log details", ex);
        }
        return eventEntity;
    }

    private String trimToMaxLength(String detail) {
        if (detail != null && detail.length() > maxDetailLength) {
            // (maxDetailLength - 3) takes "..." into account
            String result = detail.substring(0, maxDetailLength - 3).concat("...");
            LOG.warn("Detail was truncated to " + result);
            return result;
        } else {
            return detail;
        }
    }

}
