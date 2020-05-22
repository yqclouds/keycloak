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

package org.keycloak.policy;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class HistoryPasswordPolicyProvider implements PasswordPolicyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(HistoryPasswordPolicyProvider.class);
    private static final String ERROR_MESSAGE = "invalidPasswordHistoryMessage";

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private UserCredentialManager userCredentialManager;

    @Override
    public PolicyError validate(String username, String password) {
        return null;
    }

    @Autowired
    private Map<String, PasswordHashProvider> passwordHashProviders;

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = keycloakContext.getRealm().getPasswordPolicy();
        int passwordHistoryPolicyValue = policy.getPolicyConfig(PasswordPolicy.PASSWORD_HISTORY_ID);
        if (passwordHistoryPolicyValue != -1) {
            List<CredentialModel> storedPasswords = userCredentialManager.getStoredCredentialsByType(realm, user, PasswordCredentialModel.TYPE);
            for (CredentialModel cred : storedPasswords) {
                PasswordCredentialModel passwordCredential = PasswordCredentialModel.createFromCredentialModel(cred);
                PasswordHashProvider hash = passwordHashProviders.get(passwordCredential.getPasswordCredentialData().getAlgorithm());
                if (hash == null) continue;
                if (hash.verify(password, passwordCredential)) {
                    return new PolicyError(ERROR_MESSAGE, passwordHistoryPolicyValue);
                }
            }

            if (passwordHistoryPolicyValue > 0) {
                List<CredentialModel> passwordHistory = userCredentialManager.getStoredCredentialsByType(realm, user, PasswordCredentialModel.PASSWORD_HISTORY);
                List<CredentialModel> recentPasswordHistory = getRecent(passwordHistory, passwordHistoryPolicyValue - 1);
                for (CredentialModel cred : recentPasswordHistory) {
                    PasswordCredentialModel passwordCredential = PasswordCredentialModel.createFromCredentialModel(cred);
                    PasswordHashProvider hash = passwordHashProviders.get(passwordCredential.getPasswordCredentialData().getAlgorithm());
                    if (hash.verify(password, passwordCredential)) {
                        return new PolicyError(ERROR_MESSAGE, passwordHistoryPolicyValue);
                    }

                }
            }
        }
        return null;
    }

    private List<CredentialModel> getRecent(List<CredentialModel> passwordHistory, int limit) {
        return passwordHistory.stream()
                .sorted(CredentialModel.comparingByStartDateDesc())
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, HistoryPasswordPolicyProviderFactory.DEFAULT_VALUE);
    }

    @Override
    public void close() {
    }

}
