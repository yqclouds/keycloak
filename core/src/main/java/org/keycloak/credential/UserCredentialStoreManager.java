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
import org.keycloak.common.util.reflections.Types;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.models.cache.UserCache;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageManager;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.federated.UserFederatedUserCredentialStore;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserCredentialStoreManager implements UserCredentialManager, OnUserCache {
    @Autowired
    private UserStorageManager userStorageManager;
    @Autowired
    private UserFederatedUserCredentialStore userFederatedUserCredentialStore;
    @Autowired
    private UserCache userCache;

    @Autowired
    private List<CredentialProviderFactory> credentialProviderFactories;
    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    public <T> List<T> getCredentialProviders(RealmModel realm, Class<T> type) {
        List<T> list = new LinkedList<T>();
        for (ProviderFactory f : credentialProviderFactories) {
            if (!Types.supports(type, f, CredentialProviderFactory.class)) continue;
            list.add((T) credentialProviders.get(f.getId()));
        }
        return list;
    }

    protected UserCredentialStore getStoreForUser(UserModel user) {
        if (StorageId.isLocalStorage(user)) {
            return (UserCredentialStore) userStorageManager;
        } else {
            return (UserCredentialStore) userFederatedUserCredentialStore;
        }
    }

    @Override
    public void updateCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        throwExceptionIfInvalidUser(user);
        getStoreForUser(user).updateCredential(realm, user, cred);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        throwExceptionIfInvalidUser(user);
        return getStoreForUser(user).createCredential(realm, user, cred);
    }

    @Override
    public boolean removeStoredCredential(RealmModel realm, UserModel user, String id) {
        throwExceptionIfInvalidUser(user);
        boolean removalResult = getStoreForUser(user).removeStoredCredential(realm, user, id);
        userCache.evict(realm, user);
        return removalResult;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realm, UserModel user, String id) {
        return getStoreForUser(user).getStoredCredentialById(realm, user, id);
    }

    @Override
    public List<CredentialModel> getStoredCredentials(RealmModel realm, UserModel user) {
        return getStoreForUser(user).getStoredCredentials(realm, user);
    }

    @Override
    public List<CredentialModel> getStoredCredentialsByType(RealmModel realm, UserModel user, String type) {
        return getStoreForUser(user).getStoredCredentialsByType(realm, user, type);
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realm, UserModel user, String name, String type) {
        return getStoreForUser(user).getStoredCredentialByNameAndType(realm, user, name, type);
    }

    @Override
    public boolean moveCredentialTo(RealmModel realm, UserModel user, String id, String newPreviousCredentialId) {
        throwExceptionIfInvalidUser(user);
        return getStoreForUser(user).moveCredentialTo(realm, user, id, newPreviousCredentialId);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput... inputs) {
        return isValid(realm, user, Arrays.asList(inputs));
    }

    @Override
    public CredentialModel createCredentialThroughProvider(RealmModel realm, UserModel user, CredentialModel model) {
        throwExceptionIfInvalidUser(user);
        List<CredentialProvider> credentialProviders = this.credentialProviderFactories.stream()
                .map(f -> this.credentialProviders.get(f.getId()))
                .filter(provider -> provider.getType().equals(model.getType()))
                .collect(Collectors.toList());
        if (credentialProviders.isEmpty()) {
            return null;
        } else {
            return credentialProviders.get(0).createCredential(realm, user, credentialProviders.get(0).getCredentialFromModel(model));
        }
    }

    @Override
    public void updateCredentialLabel(RealmModel realm, UserModel user, String credentialId, String userLabel) {
        throwExceptionIfInvalidUser(user);
        CredentialModel credential = getStoredCredentialById(realm, user, credentialId);
        credential.setUserLabel(userLabel);
        getStoreForUser(user).updateCredential(realm, user, credential);
        if (userCache != null) {
            userCache.evict(realm, user);
        }
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, List<CredentialInput> inputs) {
        if (!isValid(user)) {
            return false;
        }
        List<CredentialInput> toValidate = new LinkedList<>(inputs);
        if (!StorageId.isLocalStorage(user)) {
            String providerId = StorageId.resolveProviderId(user);
            UserStorageProvider provider = userStorageManager.getStorageProvider(realm, providerId);
            if (provider instanceof CredentialInputValidator) {
                if (!UserStorageManager.isStorageProviderEnabled(realm, providerId)) return false;
                Iterator<CredentialInput> it = toValidate.iterator();
                while (it.hasNext()) {
                    CredentialInput input = it.next();
                    CredentialInputValidator validator = (CredentialInputValidator) provider;
                    if (validator.supportsCredentialType(input.getType()) && validator.isValid(realm, user, input)) {
                        it.remove();
                    }
                }
            }
        } else {
            if (user.getFederationLink() != null) {
                UserStorageProvider provider = userStorageManager.getStorageProvider(realm, user.getFederationLink());
                if (provider instanceof CredentialInputValidator) {
                    if (!UserStorageManager.isStorageProviderEnabled(realm, user.getFederationLink())) return false;
                    validate(realm, user, toValidate, ((CredentialInputValidator) provider));
                }
            }
        }

        if (toValidate.isEmpty()) return true;

        List<CredentialInputValidator> credentialProviders = getCredentialProviders(realm, CredentialInputValidator.class);
        for (CredentialInputValidator validator : credentialProviders) {
            validate(realm, user, toValidate, validator);

        }
        return toValidate.isEmpty();
    }

    private void validate(RealmModel realm, UserModel user, List<CredentialInput> toValidate, CredentialInputValidator validator) {
        Iterator<CredentialInput> it = toValidate.iterator();
        while (it.hasNext()) {
            CredentialInput input = it.next();
            if (validator.supportsCredentialType(input.getType()) && validator.isValid(realm, user, input)) {
                it.remove();
            }
        }
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!StorageId.isLocalStorage(user)) {
            String providerId = StorageId.resolveProviderId(user);
            UserStorageProvider provider = userStorageManager.getStorageProvider(realm, providerId);
            if (provider instanceof CredentialInputUpdater) {
                if (!UserStorageManager.isStorageProviderEnabled(realm, providerId)) return false;
                CredentialInputUpdater updater = (CredentialInputUpdater) provider;
                if (updater.supportsCredentialType(input.getType())) {
                    if (updater.updateCredential(realm, user, input)) return true;
                }

            }
        } else {
            throwExceptionIfInvalidUser(user);
            if (user.getFederationLink() != null) {
                UserStorageProvider provider = userStorageManager.getStorageProvider(realm, user.getFederationLink());
                if (provider instanceof CredentialInputUpdater) {
                    if (!UserStorageManager.isStorageProviderEnabled(realm, user.getFederationLink())) return false;
                    if (((CredentialInputUpdater) provider).updateCredential(realm, user, input)) return true;
                }
            }
        }

        List<CredentialInputUpdater> credentialProviders = getCredentialProviders(realm, CredentialInputUpdater.class);
        for (CredentialInputUpdater updater : credentialProviders) {
            if (!updater.supportsCredentialType(input.getType())) continue;
            if (updater.updateCredential(realm, user, input)) return true;

        }

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!StorageId.isLocalStorage(user)) {
            String providerId = StorageId.resolveProviderId(user);
            UserStorageProvider provider = userStorageManager.getStorageProvider(realm, providerId);
            if (provider instanceof CredentialInputUpdater) {
                if (!UserStorageManager.isStorageProviderEnabled(realm, providerId)) return;
                CredentialInputUpdater updater = (CredentialInputUpdater) provider;
                if (updater.supportsCredentialType(credentialType)) {
                    updater.disableCredentialType(realm, user, credentialType);
                }

            }
        } else {
            throwExceptionIfInvalidUser(user);
            if (user.getFederationLink() != null) {
                UserStorageProvider provider = userStorageManager.getStorageProvider(realm, user.getFederationLink());
                if (provider instanceof CredentialInputUpdater) {
                    if (!UserStorageManager.isStorageProviderEnabled(realm, user.getFederationLink())) return;
                    ((CredentialInputUpdater) provider).disableCredentialType(realm, user, credentialType);
                }
            }

        }

        List<CredentialInputUpdater> credentialProviders = getCredentialProviders(realm, CredentialInputUpdater.class);
        for (CredentialInputUpdater updater : credentialProviders) {
            if (!updater.supportsCredentialType(credentialType)) continue;
            updater.disableCredentialType(realm, user, credentialType);

        }


    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        Set<String> types = new HashSet<>();
        if (!StorageId.isLocalStorage(user)) {
            String providerId = StorageId.resolveProviderId(user);
            UserStorageProvider provider = userStorageManager.getStorageProvider(realm, providerId);
            if (provider instanceof CredentialInputUpdater) {
                if (!UserStorageManager.isStorageProviderEnabled(realm, providerId)) return Collections.EMPTY_SET;
                CredentialInputUpdater updater = (CredentialInputUpdater) provider;
                types.addAll(updater.getDisableableCredentialTypes(realm, user));
            }
        } else {
            if (user.getFederationLink() != null) {
                UserStorageProvider provider = userStorageManager.getStorageProvider(realm, user.getFederationLink());
                if (provider instanceof CredentialInputUpdater) {
                    if (!UserStorageManager.isStorageProviderEnabled(realm, user.getFederationLink()))
                        return Collections.EMPTY_SET;
                    types.addAll(((CredentialInputUpdater) provider).getDisableableCredentialTypes(realm, user));
                }
            }

        }

        List<CredentialInputUpdater> credentialProviders = getCredentialProviders(realm, CredentialInputUpdater.class);
        for (CredentialInputUpdater updater : credentialProviders) {
            types.addAll(updater.getDisableableCredentialTypes(realm, user));
        }
        return types;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String type) {
        UserStorageCredentialConfigured userStorageConfigured = isConfiguredThroughUserStorage(realm, user, type);

        // Check if we can rely just on userStorage to decide if credential is configured for the user or not
        switch (userStorageConfigured) {
            case CONFIGURED:
                return true;
            case USER_STORAGE_DISABLED:
                return false;
        }

        // Check locally as a fallback
        return isConfiguredLocally(realm, user, type);
    }

    private UserStorageCredentialConfigured isConfiguredThroughUserStorage(RealmModel realm, UserModel user, String type) {
        if (!StorageId.isLocalStorage(user)) {
            String providerId = StorageId.resolveProviderId(user);
            UserStorageProvider provider = userStorageManager.getStorageProvider(realm, providerId);
            if (provider instanceof CredentialInputValidator) {
                if (!UserStorageManager.isStorageProviderEnabled(realm, providerId))
                    return UserStorageCredentialConfigured.USER_STORAGE_DISABLED;
                CredentialInputValidator validator = (CredentialInputValidator) provider;
                if (validator.supportsCredentialType(type) && validator.isConfiguredFor(realm, user, type)) {
                    return UserStorageCredentialConfigured.CONFIGURED;
                }
            }
        } else {
            if (user.getFederationLink() != null) {
                UserStorageProvider provider = userStorageManager.getStorageProvider(realm, user.getFederationLink());
                if (provider instanceof CredentialInputValidator) {
                    if (!UserStorageManager.isStorageProviderEnabled(realm, user.getFederationLink()))
                        return UserStorageCredentialConfigured.USER_STORAGE_DISABLED;
                    if (((CredentialInputValidator) provider).isConfiguredFor(realm, user, type))
                        return UserStorageCredentialConfigured.CONFIGURED;
                }
            }

        }

        return UserStorageCredentialConfigured.NOT_CONFIGURED;
    }

    @Override
    public boolean isConfiguredLocally(RealmModel realm, UserModel user, String type) {
        List<CredentialInputValidator> credentialProviders = getCredentialProviders(realm, CredentialInputValidator.class);
        for (CredentialInputValidator validator : credentialProviders) {
            if (validator.supportsCredentialType(type) && validator.isConfiguredFor(realm, user, type)) {
                return true;
            }

        }
        return false;
    }

    @Override
    public CredentialValidationOutput authenticate(RealmModel realm, CredentialInput input) {
        List<CredentialAuthentication> list = userStorageManager.getEnabledStorageProviders(realm, CredentialAuthentication.class);
        for (CredentialAuthentication auth : list) {
            if (auth.supportsCredentialAuthenticationFor(input.getType())) {
                CredentialValidationOutput output = auth.authenticate(realm, input);
                if (output != null) return output;
            }
        }

        list = getCredentialProviders(realm, CredentialAuthentication.class);
        for (CredentialAuthentication auth : list) {
            if (auth.supportsCredentialAuthenticationFor(input.getType())) {
                CredentialValidationOutput output = auth.authenticate(realm, input);
                if (output != null) return output;
            }
        }

        return null;
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<OnUserCache> credentialProviders = getCredentialProviders(realm, OnUserCache.class);
        for (OnUserCache validator : credentialProviders) {
            validator.onCache(realm, user, delegate);
        }
    }

    @Override
    public List<String> getConfiguredUserStorageCredentialTypes(RealmModel realm, UserModel user) {
        List<CredentialProvider> credentialProviders = getCredentialProviders(realm, CredentialProvider.class);

        return credentialProviders.stream().map(CredentialProvider::getType)
                .filter(credentialType -> UserStorageCredentialConfigured.CONFIGURED == isConfiguredThroughUserStorage(realm, user, credentialType))
                .collect(Collectors.toList());
    }

    @Override
    public void close() {

    }

    private boolean isValid(UserModel user) {
        return user != null && user.getServiceAccountClientLink() == null;
    }

    private void throwExceptionIfInvalidUser(UserModel user) {
        if (user == null || isValid(user)) {
            return;
        }
        throw new RuntimeException("You can not manage credentials for this user");
    }

    private enum UserStorageCredentialConfigured {
        CONFIGURED,
        USER_STORAGE_DISABLED,
        NOT_CONFIGURED
    }
}
