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

package org.keycloak.authentication;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.UriInfo;

/**
 * Interface that encapsulates the current state of the current form being executed
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface FormContext {
    /**
     * Current event builder being used
     *
     * @return
     */
    EventBuilder getEvent();

    /**
     * Create a refresh new EventBuilder to use within this context
     *
     * @return
     */
    EventBuilder newEvent();

    /**
     * The current execution in the flow
     *
     * @return
     */
    AuthenticationExecutionModel getExecution();

    /**
     * Current user attached to this flow.  It can return null if no uesr has been identified yet
     *
     * @return
     */
    UserModel getUser();

    /**
     * Attach a specific user to this flow.
     *
     * @param user
     */
    void setUser(UserModel user);

    /**
     * Current realm
     *
     * @return
     */
    RealmModel getRealm();

    /**
     * AuthenticationSessionModel attached to this flow
     *
     * @return
     */
    AuthenticationSessionModel getAuthenticationSession();

    /**
     * Information about the IP address from the connecting HTTP client.
     *
     * @return
     */
    ClientConnection getConnection();

    /**
     * UriInfo of the current request
     *
     * @return
     */
    UriInfo getUriInfo();

    /**
     * Current session
     *
     * @return
     */
    KeycloakSession getSession();

    HttpRequest getHttpRequest();

    /**
     * Get any configuration associated with the current execution
     *
     * @return
     */
    AuthenticatorConfigModel getAuthenticatorConfig();
}
