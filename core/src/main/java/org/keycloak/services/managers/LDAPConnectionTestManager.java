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

import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.models.LDAPConstants;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPContextManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LDAPConnectionTestManager {

    public static final String TEST_CONNECTION = "testConnection";
    public static final String TEST_AUTHENTICATION = "testAuthentication";
    private static final Logger LOG = LoggerFactory.getLogger(LDAPConnectionTestManager.class);

    public static boolean testLDAP(String action, String connectionUrl, String bindDn,
                                   String bindCredential, String useTruststoreSpi, String connectionTimeout, String tls) {
        if (!TEST_CONNECTION.equals(action) && !TEST_AUTHENTICATION.equals(action)) {
//            ServicesLogger.LOGGER.unknownAction(action);
            return false;
        }


        // Prepare MultivaluedHashMap so that it is usable in LDAPContext class
        MultivaluedHashMap<String, String> ldapConfig = new MultivaluedHashMap<>();

        if (connectionUrl == null) {
            LOG.error("Unknown connection URL");
            return false;
        }
        ldapConfig.putSingle(LDAPConstants.CONNECTION_URL, connectionUrl);
        ldapConfig.putSingle(LDAPConstants.USE_TRUSTSTORE_SPI, useTruststoreSpi);
        ldapConfig.putSingle(LDAPConstants.CONNECTION_TIMEOUT, connectionTimeout);
        ldapConfig.putSingle(LDAPConstants.START_TLS, tls);

        if (TEST_AUTHENTICATION.equals(action)) {
            // If AUTHENTICATION action is executed add also dn and credentials to configuration
            // LDAPContextManager is responsible for correct order of addition of credentials to context in case
            // tls is true

            if (bindDn == null) {
                LOG.error("Unknown bind DN");
                return false;
            }

            ldapConfig.putSingle(LDAPConstants.AUTH_TYPE, LDAPConstants.AUTH_TYPE_SIMPLE);
            ldapConfig.putSingle(LDAPConstants.BIND_DN, bindDn);
            ldapConfig.putSingle(LDAPConstants.BIND_CREDENTIAL, bindCredential);
        } else {
            ldapConfig.putSingle(LDAPConstants.AUTH_TYPE, LDAPConstants.AUTH_TYPE_NONE);
        }

        // Create ldapContextManager in try-with-resource so that ldapContext/tlsResponse/VaultSecret is closed/removed when it is not needed anymore
        try (LDAPContextManager ldapContextManager = LDAPContextManager.create(new LDAPConfig(ldapConfig))) {
            ldapContextManager.getLdapContext();

            // Connection was successful, no exception was raised returning true
            return true;
        } catch (Exception ne) {
            String errorMessage = (TEST_AUTHENTICATION.equals(action)) ? "Error when authenticating to LDAP: " : "Error when connecting to LDAP: ";
//            ServicesLogger.LOGGER.errorAuthenticating(ne, errorMessage + ne.getMessage());
            return false;
        }
    }
}
