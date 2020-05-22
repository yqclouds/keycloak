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

package org.keycloak.services.managers;

import org.keycloak.common.util.Base64Url;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * TODO: Remove this and probably also ClientSessionParser. It's uneccessary genericity and abstraction, which is not needed anymore when clientSessionModel was fully removed.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class CodeGenerateUtil {

    private static final Logger LOG = LoggerFactory.getLogger(CodeGenerateUtil.class);

    private static final String ACTIVE_CODE = "active_code";

    private static final Map<Class<? extends CommonClientSessionModel>, Supplier<ClientSessionParser>> PARSERS = new HashMap<>();

    static {
        PARSERS.put(AuthenticationSessionModel.class, () -> {
            return new AuthenticationSessionModelParser();
        });
    }


    static <CS extends CommonClientSessionModel> ClientSessionParser<CS> getParser(Class<CS> clientSessionClass) {
        for (Class<?> c : PARSERS.keySet()) {
            if (c.isAssignableFrom(clientSessionClass)) {
                return PARSERS.get(c).get();
            }
        }
        return null;
    }


    interface ClientSessionParser<CS extends CommonClientSessionModel> {

        CS parseSession(String code, String tabId, RealmModel realm, ClientModel client, EventBuilder event);

        String retrieveCode(CS clientSession);

        void removeExpiredSession(CS clientSession);

        boolean verifyCode(String code, CS clientSession);

        boolean isExpired(String code, CS clientSession);

        int getTimestamp(CS clientSession);

        void setTimestamp(CS clientSession, int timestamp);

        String getClientNote(CS clientSession, String noteKey);

    }


    // IMPLEMENTATIONS


    private static class AuthenticationSessionModelParser implements ClientSessionParser<AuthenticationSessionModel> {

        @Override
        public AuthenticationSessionModel parseSession(String code, String tabId, RealmModel realm, ClientModel client, EventBuilder event) {
            // Read authSessionID from cookie. Code is ignored for now
            return new AuthenticationSessionManager().getCurrentAuthenticationSession(realm, client, tabId);
        }

        @Override
        public String retrieveCode(AuthenticationSessionModel authSession) {
            String nextCode = authSession.getAuthNote(ACTIVE_CODE);
            if (nextCode == null) {
                String actionId = Base64Url.encode(KeycloakModelUtils.generateSecret());
                authSession.setAuthNote(ACTIVE_CODE, actionId);
                nextCode = actionId;
            } else {
                LOG.debug("Code already generated for authentication session, using same code");
            }

            return nextCode;
        }


        @Override
        public void removeExpiredSession(AuthenticationSessionModel clientSession) {
            new AuthenticationSessionManager().removeAuthenticationSession(clientSession.getRealm(), clientSession, true);
        }


        @Override
        public boolean verifyCode(String code, AuthenticationSessionModel authSession) {
            String activeCode = authSession.getAuthNote(ACTIVE_CODE);
            if (activeCode == null) {
                LOG.debug("Active code not found in authentication session");
                return false;
            }

            authSession.removeAuthNote(ACTIVE_CODE);

            return MessageDigest.isEqual(code.getBytes(), activeCode.getBytes());
        }


        @Override
        public boolean isExpired(String code, AuthenticationSessionModel clientSession) {
            return false;
        }

        @Override
        public int getTimestamp(AuthenticationSessionModel clientSession) {
            return clientSession.getParentSession().getTimestamp();
        }

        @Override
        public void setTimestamp(AuthenticationSessionModel clientSession, int timestamp) {
            clientSession.getParentSession().setTimestamp(timestamp);
        }

        @Override
        public String getClientNote(AuthenticationSessionModel clientSession, String noteKey) {
            return clientSession.getClientNote(noteKey);
        }
    }


}
