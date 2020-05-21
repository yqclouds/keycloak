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

package org.keycloak.events.email;

import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventModel;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEventModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class EmailEventListenerProvider implements EventListenerProvider {

    private static final Logger LOG = LoggerFactory.getLogger(EmailEventListenerProvider.class);

    private EmailTemplateProvider emailTemplateProvider;
    private Set<EventType> includedEvents;

    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private UserProvider userProvider;

    public EmailEventListenerProvider(EmailTemplateProvider emailTemplateProvider, Set<EventType> includedEvents) {
        this.emailTemplateProvider = emailTemplateProvider;
        this.includedEvents = includedEvents;
    }

    @Override
    public void onEvent(EventModel event) {
        if (includedEvents.contains(event.getType())) {
            if (event.getRealmId() != null && event.getUserId() != null) {
                RealmModel realm = realmProvider.getRealm(event.getRealmId());
                UserModel user = userProvider.getUserById(event.getUserId(), realm);
                if (user != null && user.getEmail() != null && user.isEmailVerified()) {
                    try {
                        emailTemplateProvider.setRealm(realm).setUser(user).sendEvent(event);
                    } catch (EmailException e) {
                        LOG.error("Failed to send type mail", e);
                    }
                }
            }
        }
    }

    @Override
    public void onEvent(AdminEventModel event, boolean includeRepresentation) {
    }

    @Override
    public void close() {
    }

}
