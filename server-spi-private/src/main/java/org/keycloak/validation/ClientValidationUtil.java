/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.validation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.BadRequestException;

public class ClientValidationUtil {
    @Autowired(required = false)
    private ClientValidationProvider clientValidationProvider;

    public void validate(KeycloakSession session, ClientModel client, boolean create, ErrorHandler errorHandler) throws BadRequestException {
        if (clientValidationProvider != null) {
            DefaultClientValidationContext context = new DefaultClientValidationContext(create ? ClientValidationContext.Event.CREATE : ClientValidationContext.Event.UPDATE, session, client);
            clientValidationProvider.validate(context);

            if (!context.isValid()) {
                errorHandler.onError(context);
            }
        }
    }

    public interface ErrorHandler {

        void onError(ClientValidationContext context);

    }

    private static class DefaultClientValidationContext implements ClientValidationContext {

        private Event event;
        private KeycloakSession session;
        private ClientModel client;

        private String error;

        public DefaultClientValidationContext(Event event, KeycloakSession session, ClientModel client) {
            this.event = event;
            this.session = session;
            this.client = client;
        }

        public boolean isValid() {
            return error == null;
        }

        public String getError() {
            return error;
        }

        @Override
        public Event getEvent() {
            return event;
        }

        @Override
        public KeycloakSession getSession() {
            return session;
        }

        @Override
        public ClientModel getClient() {
            return client;
        }

        @Override
        public ClientValidationContext invalid(String error) {
            this.error = error;
            return this;
        }
    }

}
