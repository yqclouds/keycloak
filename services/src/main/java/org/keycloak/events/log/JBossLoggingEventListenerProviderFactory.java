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

package org.keycloak.events.log;

import org.jboss.logging.Logger;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;

import javax.annotation.PostConstruct;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@ProviderFactory(id = "jboss-logging", providerClasses = EventListenerProvider.class)
public class JBossLoggingEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "jboss-logging";

    private static final Logger logger = Logger.getLogger("org.keycloak.events");

    @Value("${success-level}")
    private String successLevelStr = "debug";
    @Value("${error-level}")
    private String errorLevelStr = "warn";

    private Logger.Level successLevel;
    private Logger.Level errorLevel;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new JBossLoggingEventListenerProvider(session, logger, successLevel, errorLevel);
    }

    @PostConstruct
    public void afterPropertiesSet() {
        successLevel = Logger.Level.valueOf(successLevelStr.toUpperCase());
        errorLevel = Logger.Level.valueOf(errorLevelStr.toUpperCase());
    }

    @Override
    public String getId() {
        return ID;
    }
}
