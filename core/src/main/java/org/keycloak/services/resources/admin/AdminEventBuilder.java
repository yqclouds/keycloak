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
package org.keycloak.services.resources.admin;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEventModel;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AdminEventBuilder {

    protected static final Logger LOG = LoggerFactory.getLogger(AdminEventBuilder.class);

    @Autowired(required = false)
    private EventStoreProvider eventStoreProvider;
    private Map<String, EventListenerProvider> listeners;
    private RealmModel realm;
    private AdminEventModel adminEvent;

    public AdminEventBuilder(RealmModel realm, AdminAuth auth, ClientConnection clientConnection) {
        this.realm = realm;
        adminEvent = new AdminEventModel();

        this.listeners = new HashMap<>();
        updateStore();
        addListeners();

        authRealm(auth.getRealm());
        authClient(auth.getClient());
        authUser(auth.getUser());
        authIpAddress(clientConnection.getRemoteAddr());
    }

    public AdminEventBuilder realm(RealmModel realm) {
        adminEvent.setRealmId(realm.getId());
        return this;
    }

    public AdminEventBuilder realm(String realmId) {
        adminEvent.setRealmId(realmId);
        return this;
    }

    /**
     * Refreshes the builder assuming that the realm event information has
     * changed. Thought to be used when the updateRealmEventsConfig has
     * modified the events configuration. Now the store and the listeners are
     * updated to have previous and new setup.
     *
     * @return The same builder
     */
    public AdminEventBuilder refreshRealmEventsConfig() {
        return this.updateStore().addListeners();
    }

    private AdminEventBuilder updateStore() {
        if (realm.isAdminEventsEnabled() && eventStoreProvider == null) {
            // ServicesLogger.LOGGER.noEventStoreProvider();
        }
        return this;
    }

    @Autowired
    private Map<String, EventListenerProvider> eventListenerProviders;

    private AdminEventBuilder addListeners() {
        Set<String> extraListeners = realm.getEventsListeners();
        if (extraListeners != null && !extraListeners.isEmpty()) {
            for (String id : extraListeners) {
                if (!listeners.containsKey(id)) {
                    EventListenerProvider listener = eventListenerProviders.get(id);
                    if (listener != null) {
                        listeners.put(id, listener);
                    } else {
                        // ServicesLogger.LOGGER.providerNotFound(id);
                    }
                }
            }
        }
        return this;
    }

    public AdminEventBuilder operation(OperationType operationType) {
        adminEvent.setOperationType(operationType);
        return this;
    }

    public AdminEventBuilder resource(ResourceType resourceType) {
        adminEvent.setResourceType(resourceType);
        return this;
    }

    /**
     * Setter for custom resource types with values different from {@link ResourceType}.
     */
    public AdminEventBuilder resource(String resourceType) {
        adminEvent.setResourceTypeAsString(resourceType);
        return this;
    }

    public AdminEventBuilder authRealm(RealmModel realm) {
        AuthDetails authDetails = adminEvent.getAuthDetails();
        if (authDetails == null) {
            authDetails = new AuthDetails();
            authDetails.setRealmId(realm.getId());
        } else {
            authDetails.setRealmId(realm.getId());
        }
        adminEvent.setAuthDetails(authDetails);
        return this;
    }

    public AdminEventBuilder authClient(ClientModel client) {
        AuthDetails authDetails = adminEvent.getAuthDetails();
        if (authDetails == null) {
            authDetails = new AuthDetails();
            authDetails.setClientId(client.getId());
        } else {
            authDetails.setClientId(client.getId());
        }
        adminEvent.setAuthDetails(authDetails);
        return this;
    }

    public AdminEventBuilder authUser(UserModel user) {
        AuthDetails authDetails = adminEvent.getAuthDetails();
        if (authDetails == null) {
            authDetails = new AuthDetails();
            authDetails.setUserId(user.getId());
        } else {
            authDetails.setUserId(user.getId());
        }
        adminEvent.setAuthDetails(authDetails);
        return this;
    }

    public AdminEventBuilder authIpAddress(String ipAddress) {
        AuthDetails authDetails = adminEvent.getAuthDetails();
        if (authDetails == null) {
            authDetails = new AuthDetails();
            authDetails.setIpAddress(ipAddress);
        } else {
            authDetails.setIpAddress(ipAddress);
        }
        adminEvent.setAuthDetails(authDetails);
        return this;
    }

    public AdminEventBuilder resourcePath(String... pathElements) {
        StringBuilder sb = new StringBuilder();
        for (String element : pathElements) {
            sb.append("/");
            sb.append(element);
        }
        if (pathElements.length > 0) sb.deleteCharAt(0); // remove leading '/'

        adminEvent.setResourcePath(sb.toString());
        return this;
    }

    public AdminEventBuilder resourcePath(UriInfo uriInfo) {
        String path = getResourcePath(uriInfo);
        adminEvent.setResourcePath(path);
        return this;
    }

    public AdminEventBuilder resourcePath(UriInfo uriInfo, String id) {
        StringBuilder sb = new StringBuilder();
        sb.append(getResourcePath(uriInfo));
        sb.append("/");
        sb.append(id);
        adminEvent.setResourcePath(sb.toString());
        return this;
    }

    private String getResourcePath(UriInfo uriInfo) {
        String path = uriInfo.getPath();

        StringBuilder sb = new StringBuilder();
        sb.append("/realms/");
        sb.append(realm.getName());
        sb.append("/");
        String realmRelative = sb.toString();

        return path.substring(path.indexOf(realmRelative) + realmRelative.length());
    }

    public AdminEventBuilder representation(Object value) {
        if (value == null || value.equals("")) {
            return this;
        }
        try {
            adminEvent.setRepresentation(JsonSerialization.writeValueAsString(value));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return this;
    }

    public AdminEventModel getEvent() {
        return adminEvent;
    }

    public void success() {
        send();
    }

    private void send() {
        boolean includeRepresentation = false;
        if (realm.isAdminEventsDetailsEnabled()) {
            includeRepresentation = true;
        }
        adminEvent.setTime(Time.currentTimeMillis());

        if (eventStoreProvider != null) {
            try {
                eventStoreProvider.onEvent(adminEvent, includeRepresentation);
            } catch (Throwable t) {
                // ServicesLogger.LOGGER.failedToSaveEvent(t);
            }
        }

        if (listeners != null) {
            for (EventListenerProvider l : listeners.values()) {
                try {
                    l.onEvent(adminEvent, includeRepresentation);
                } catch (Throwable t) {
                    // ServicesLogger.LOGGER.failedToSendType(t, l);
                }
            }
        }
    }

}
