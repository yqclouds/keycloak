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
package org.keycloak.services.resources;

import org.keycloak.common.util.Resteasy;
import org.keycloak.services.error.KeycloakErrorHandler;
import org.keycloak.services.filters.KeycloakTransactionCommitter;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.util.ObjectMapperResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class KeycloakApplication extends Application {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakApplication.class);

    public static final AtomicBoolean BOOTSTRAP_ADMIN_USER = new AtomicBoolean(false);

    protected Set<Object> singletons = new HashSet<>();
    protected Set<Class<?>> classes = new HashSet<>();

    public KeycloakApplication() {
        LOG.debug("RestEasy provider: {}", Resteasy.getProvider().getClass().getName());

        Resteasy.pushDefaultContextObject(KeycloakApplication.class, this);
        Resteasy.pushContext(KeycloakApplication.class, this); // for injection

        singletons.add(new RobotsResource());
        singletons.add(new RealmsResource());
        singletons.add(new AdminRoot());

        classes.add(ThemeResource.class);
        classes.add(JsResource.class);
        classes.add(KeycloakTransactionCommitter.class);
        classes.add(KeycloakErrorHandler.class);

        singletons.add(new ObjectMapperResolver(Boolean.parseBoolean(System.getProperty("keycloak.jsonPrettyPrint", "false"))));
        singletons.add(new WelcomeResource());
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }
}
