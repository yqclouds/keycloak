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

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultPasswordPolicyManagerProvider implements PasswordPolicyManagerProvider {
    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        for (PasswordPolicyProvider p : getProviders(realm)) {
            PolicyError policyError = p.validate(realm, user, password);
            if (policyError != null) {
                return policyError;
            }
        }
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        for (PasswordPolicyProvider p : getProviders()) {
            PolicyError policyError = p.validate(user, password);
            if (policyError != null) {
                return policyError;
            }
        }
        return null;
    }

    @Override
    public void close() {
    }

    @Autowired
    private KeycloakContext keycloakContext;

    private List<PasswordPolicyProvider> getProviders() {
        return getProviders(keycloakContext.getRealm());

    }

    @Autowired
    private Map<String, PasswordPolicyProvider> passwordPolicyProviders;

    private List<PasswordPolicyProvider> getProviders(RealmModel realm) {
        LinkedList<PasswordPolicyProvider> list = new LinkedList<>();
        PasswordPolicy policy = realm.getPasswordPolicy();
        for (String id : policy.getPolicies()) {
            PasswordPolicyProvider provider = passwordPolicyProviders.get(id);
            list.add(provider);
        }
        return list;
    }

}
