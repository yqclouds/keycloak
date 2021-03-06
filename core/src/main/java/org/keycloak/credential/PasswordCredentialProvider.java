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
package org.keycloak.credential;

import com.hsbc.unified.iam.core.credential.CredentialInput;
import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.facade.model.credential.UserCredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PasswordCredentialProvider implements CredentialProvider<PasswordCredentialModel>, CredentialInputUpdater, CredentialInputValidator {

    public static final String PASSWORD_CACHE_KEY = PasswordCredentialProvider.class.getName() + "." + PasswordCredentialModel.TYPE;
    private static final Logger LOG = LoggerFactory.getLogger(PasswordCredentialProvider.class);

    @Autowired
    private UserCredentialManager userCredentialManager;

    protected UserCredentialStore getCredentialStore() {
        return userCredentialManager;
    }

    public PasswordCredentialModel getPassword(RealmModel realm, UserModel user) {
        List<CredentialModel> passwords = null;
        // if the model was marked for eviction while passwords were initialized, override it from credentialStore
        passwords = getCredentialStore().getStoredCredentialsByType(realm, user, getType());
        if (passwords == null || passwords.isEmpty()) return null;

        return PasswordCredentialModel.createFromCredentialModel(passwords.get(0));
    }

    @Autowired
    private PasswordPolicyManagerProvider passwordPolicyManagerProvider;

    public boolean createCredential(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = realm.getPasswordPolicy();

        PolicyError error = passwordPolicyManagerProvider.validate(realm, user, password);
        if (error != null) throw new ModelException(error.getMessage(), error.getParameters());

        PasswordHashProvider hash = getHashProvider(policy);
        if (hash == null) {
            return false;
        }
        PasswordCredentialModel credentialModel = hash.encodedCredential(password, policy.getHashIterations());
        credentialModel.setCreatedDate(Time.currentTimeMillis());
        createCredential(realm, user, credentialModel);
        return true;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PasswordCredentialModel credentialModel) {

        PasswordPolicy policy = realm.getPasswordPolicy();
        int expiredPasswordsPolicyValue = policy.getExpiredPasswords();

        // 1) create new or reset existing password
        CredentialModel createdCredential;
        CredentialModel oldPassword = getPassword(realm, user);
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        if (oldPassword == null) { // no password exists --> create new
            createdCredential = getCredentialStore().createCredential(realm, user, credentialModel);
        } else { // password exists --> update existing
            credentialModel.setId(oldPassword.getId());
            getCredentialStore().updateCredential(realm, user, credentialModel);
            createdCredential = credentialModel;

            // 2) add a password history item based on the old password
            if (expiredPasswordsPolicyValue > 1) {
                oldPassword.setId(null);
                oldPassword.setType(PasswordCredentialModel.PASSWORD_HISTORY);
                getCredentialStore().createCredential(realm, user, oldPassword);
            }
        }

        // 3) remove old password history items
        List<CredentialModel> passwordHistoryList = getCredentialStore().getStoredCredentialsByType(realm, user, PasswordCredentialModel.PASSWORD_HISTORY);
        final int passwordHistoryListMaxSize = Math.max(0, expiredPasswordsPolicyValue - 1);
        if (passwordHistoryList.size() > passwordHistoryListMaxSize) {
            passwordHistoryList.stream()
                    .sorted(CredentialModel.comparingByStartDateDesc())
                    .skip(passwordHistoryListMaxSize)
                    .forEach(p -> getCredentialStore().removeStoredCredential(realm, user, p.getId()));
        }
        return createdCredential;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public PasswordCredentialModel getCredentialFromModel(CredentialModel model) {
        return PasswordCredentialModel.createFromCredentialModel(model);
    }

    @Autowired
    private Map<String, PasswordHashProvider> passwordHashProviders;

    protected PasswordHashProvider getHashProvider(PasswordPolicy policy) {
        PasswordHashProvider hash = passwordHashProviders.get(policy.getHashAlgorithm());
        if (hash == null) {
            LOG.warn("Realm PasswordPolicy PasswordHashProvider {} not found", policy.getHashAlgorithm());
            return passwordHashProviders.get(PasswordPolicy.HASH_ALGORITHM_DEFAULT);
        }
        return hash;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(getType());
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        return createCredential(realm, user, input.getChallengeResponse());
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.emptySet();
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return getPassword(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            LOG.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;

        }
        if (input.getChallengeResponse() == null) {
            LOG.debug("Input password was null for user {} ", user.getUsername());
            return false;
        }
        PasswordCredentialModel password = getPassword(realm, user);
        if (password == null) {
            LOG.debug("No password cached or stored for user {} ", user.getUsername());
            return false;
        }
        PasswordHashProvider hash = passwordHashProviders.get(password.getPasswordCredentialData().getAlgorithm());
        if (hash == null) {
            LOG.debug("PasswordHashProvider {} not found for user {} ", password.getPasswordCredentialData().getAlgorithm(), user.getUsername());
            return false;
        }
        if (!hash.verify(input.getChallengeResponse(), password)) {
            LOG.debug("Failed password validation for user {} ", user.getUsername());
            return false;
        }
        PasswordPolicy policy = realm.getPasswordPolicy();
        if (policy == null) {
            return true;
        }
        hash = getHashProvider(policy);
        if (hash == null) {
            return true;
        }
        if (hash.policyCheck(policy, password)) {
            return true;
        }

        PasswordCredentialModel newPassword = hash.encodedCredential(input.getChallengeResponse(), policy.getHashIterations());
        newPassword.setId(password.getId());
        newPassword.setCreatedDate(password.getCreatedDate());
        newPassword.setUserLabel(password.getUserLabel());
        getCredentialStore().updateCredential(realm, user, newPassword);

        return true;
    }

    @Override
    public String getType() {
        return PasswordCredentialModel.TYPE;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        CredentialTypeMetadata.CredentialTypeMetadataBuilder metadataBuilder = CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("password-display-name")
                .helpText("password-help-text")
                .iconCssClass("kcAuthenticatorPasswordClass");

        // Check if we are creating or updating password
        UserModel user = metadataContext.getUser();
        if (user != null && userCredentialManager.isConfiguredFor(keycloakContext.getRealm(), user, getType())) {
            metadataBuilder.updateAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        } else {
            metadataBuilder.createAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        }

        return metadataBuilder
                .removeable(false)
                .build();
    }
}
