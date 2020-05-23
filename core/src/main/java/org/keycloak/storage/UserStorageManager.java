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

package org.keycloak.storage;

import org.keycloak.common.util.reflections.Types;
import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.ComponentUtil;
import org.keycloak.models.utils.ReadOnlyUserModelDelegate;
import org.keycloak.services.managers.UserStorageSyncManager;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.storage.user.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpSession;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserStorageManager implements UserProvider, OnUserCache, OnCreateComponent, OnUpdateComponent {
    private static final Logger LOG = LoggerFactory.getLogger(UserStorageManager.class);

    private HttpSession httpSession;

    @Autowired
    private Map<String, UserStorageProviderFactory> userStorageProviderFactories;

    public static boolean isStorageProviderEnabled(RealmModel realm, String providerId) {
        UserStorageProviderModel model = getStorageProviderModel(realm, providerId);
        return model.isEnabled();
    }

    public static List<UserStorageProviderModel> getStorageProviders(RealmModel realm) {
        return realm.getUserStorageProviders();
    }

    public UserStorageProvider getStorageProviderInstance(UserStorageProviderModel model, UserStorageProviderFactory factory) {
        UserStorageProvider instance = (UserStorageProvider) httpSession.getAttribute(model.getId());
        if (instance != null) return instance;
        instance = (UserStorageProvider) factory.create(model);
        if (instance == null) {
            throw new IllegalStateException("UserStorageProvideFactory (of type " + factory.getClass().getName() + ") produced a null instance");
        }
        // session.enlistForClose(instance);
        httpSession.setAttribute(model.getId(), instance);
        return instance;
    }

    public <T> List<T> getStorageProviders(RealmModel realm, Class<T> type) {
        List<T> list = new LinkedList<>();
        for (UserStorageProviderModel model : getStorageProviders(realm)) {
            UserStorageProviderFactory factory = userStorageProviderFactories.get(model.getProviderId());
            if (factory == null) {
                LOG.warn("Configured UserStorageProvider {} of provider id {} does not exist in realm {}", model.getName(), model.getProviderId(), realm.getName());
                continue;
            }
            if (Types.supports(type, factory, UserStorageProviderFactory.class)) {
                list.add(type.cast(getStorageProviderInstance(model, factory)));
            }


        }
        return list;
    }

    public <T> List<T> getEnabledStorageProviders(RealmModel realm, Class<T> type) {
        List<T> list = new LinkedList<>();
        for (UserStorageProviderModel model : getStorageProviders(realm)) {
            if (!model.isEnabled()) continue;
            UserStorageProviderFactory factory = userStorageProviderFactories.get(model.getProviderId());
            if (factory == null) {
                LOG.warn("Configured UserStorageProvider {} of provider id {} does not exist in realm {}", model.getName(), model.getProviderId(), realm.getName());
                continue;
            }
            if (Types.supports(type, factory, UserStorageProviderFactory.class)) {
                list.add(type.cast(getStorageProviderInstance(model, factory)));
            }


        }
        return list;
    }

    public static UserStorageProviderModel getStorageProviderModel(RealmModel realm, String componentId) {
        ComponentModel model = realm.getComponent(componentId);
        if (model == null) return null;
        return new UserStorageProviderModel(model);
    }

    public UserStorageProvider getStorageProvider(RealmModel realm, String componentId) {
        ComponentModel model = realm.getComponent(componentId);
        if (model == null) return null;
        UserStorageProviderModel storageModel = new UserStorageProviderModel(model);
        UserStorageProviderFactory factory = userStorageProviderFactories.get(model.getProviderId());
        if (factory == null) {
            throw new ModelException("Could not find UserStorageProviderFactory for: " + model.getProviderId());
        }
        return getStorageProviderInstance(storageModel, factory);
    }

    @Autowired
    private UserProvider userProvider;

    protected UserProvider localStorage() {
        return userProvider;
    }

    @Override
    public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        return localStorage().addUser(realm, id, username.toLowerCase(), addDefaultRoles, addDefaultRequiredActions);
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        for (UserRegistrationProvider provider : getEnabledStorageProviders(realm, UserRegistrationProvider.class)) {
            UserModel user = provider.addUser(realm, username);
            if (user != null) return user;
        }

        return localStorage().addUser(realm, username.toLowerCase());
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        if (getFederatedStorage() != null) getFederatedStorage().preRemove(realm, user);
        StorageId storageId = new StorageId(user.getId());
        if (storageId.getProviderId() == null) {
            boolean linkRemoved = true;
            if (user.getFederationLink() != null) {
                if (isStorageProviderEnabled(realm, user.getFederationLink())) {
                    UserStorageProvider provider = getStorageProvider(realm, user.getFederationLink());
                    if (provider != null && provider instanceof UserRegistrationProvider) {
                        ((UserRegistrationProvider) provider).removeUser(realm, user);
                    }
                } else {
                    linkRemoved = false;
                }
            }
            return localStorage().removeUser(realm, user) && linkRemoved;
        }
        UserRegistrationProvider registry = (UserRegistrationProvider) getStorageProvider(realm, storageId.getProviderId());
        if (registry == null) {
            throw new ModelException("Could not resolve StorageProvider: " + storageId.getProviderId());
        }
        return registry.removeUser(realm, user);

    }

    @Autowired
    private UserFederatedStorageProvider userFederatedStorageProvider;

    public UserFederatedStorageProvider getFederatedStorage() {
        return userFederatedStorageProvider;
    }

    @Override
    public void addFederatedIdentity(RealmModel realm, UserModel user, FederatedIdentityModel socialLink) {
        if (StorageId.isLocalStorage(user)) {
            localStorage().addFederatedIdentity(realm, user, socialLink);
        } else {
            getFederatedStorage().addFederatedIdentity(realm, user.getId(), socialLink);
        }
    }

    public void updateFederatedIdentity(RealmModel realm, UserModel federatedUser, FederatedIdentityModel federatedIdentityModel) {
        if (StorageId.isLocalStorage(federatedUser)) {
            localStorage().updateFederatedIdentity(realm, federatedUser, federatedIdentityModel);

        } else {
            getFederatedStorage().updateFederatedIdentity(realm, federatedUser.getId(), federatedIdentityModel);
        }
    }

    @Override
    public boolean removeFederatedIdentity(RealmModel realm, UserModel user, String socialProvider) {
        if (StorageId.isLocalStorage(user)) {
            return localStorage().removeFederatedIdentity(realm, user, socialProvider);
        } else {
            return getFederatedStorage().removeFederatedIdentity(realm, user.getId(), socialProvider);
        }
    }

    @Override
    public void addConsent(RealmModel realm, String userId, UserConsentModel consent) {
        if (StorageId.isLocalStorage(userId)) {
            localStorage().addConsent(realm, userId, consent);
        } else {
            getFederatedStorage().addConsent(realm, userId, consent);
        }

    }

    @Override
    public UserConsentModel getConsentByClient(RealmModel realm, String userId, String clientInternalId) {
        if (StorageId.isLocalStorage(userId)) {
            return localStorage().getConsentByClient(realm, userId, clientInternalId);
        } else {
            return getFederatedStorage().getConsentByClient(realm, userId, clientInternalId);
        }
    }

    @Override
    public List<UserConsentModel> getConsents(RealmModel realm, String userId) {
        if (StorageId.isLocalStorage(userId)) {
            return localStorage().getConsents(realm, userId);

        } else {
            return getFederatedStorage().getConsents(realm, userId);
        }
    }

    @Override
    public void updateConsent(RealmModel realm, String userId, UserConsentModel consent) {
        if (StorageId.isLocalStorage(userId)) {
            localStorage().updateConsent(realm, userId, consent);
        } else {
            getFederatedStorage().updateConsent(realm, userId, consent);
        }

    }

    @Override
    public boolean revokeConsentForClient(RealmModel realm, String userId, String clientInternalId) {
        if (StorageId.isLocalStorage(userId)) {
            return localStorage().revokeConsentForClient(realm, userId, clientInternalId);
        } else {
            return getFederatedStorage().revokeConsentForClient(realm, userId, clientInternalId);
        }
    }

    @Override
    public void setNotBeforeForUser(RealmModel realm, UserModel user, int notBefore) {
        if (StorageId.isLocalStorage(user)) {
            localStorage().setNotBeforeForUser(realm, user, notBefore);
        } else {
            getFederatedStorage().setNotBeforeForUser(realm, user.getId(), notBefore);
        }
    }

    @Override
    public int getNotBeforeOfUser(RealmModel realm, UserModel user) {
        if (StorageId.isLocalStorage(user)) {
            return localStorage().getNotBeforeOfUser(realm, user);

        } else {
            return getFederatedStorage().getNotBeforeOfUser(realm, user.getId());
        }
    }

    /**
     * Allows a UserStorageProvider to proxy and/or synchronize an imported user.
     *
     * @param realm
     * @param user
     * @return
     */
    protected UserModel importValidation(RealmModel realm, UserModel user) {
        if (user == null || user.getFederationLink() == null) return user;
        UserStorageProvider provider = getStorageProvider(realm, user.getFederationLink());
        if (provider != null && provider instanceof ImportedUserValidation) {
            if (!isStorageProviderEnabled(realm, user.getFederationLink())) {
                return new ReadOnlyUserModelDelegate(user) {
                    @Override
                    public boolean isEnabled() {
                        return false;
                    }
                };
            }
            UserModel validated = ((ImportedUserValidation) provider).validate(realm, user);
            if (validated == null) {
                deleteInvalidUser(realm, user);
                return null;
            } else {
                return validated;
            }

        } else if (provider == null) {
            // remove linked user with unknown storage provider.
            LOG.debug("Removed user with federation link of unknown storage provider '{}'", user.getUsername());
            deleteInvalidUser(realm, user);
            return null;
        } else {
            return user;
        }

    }

    @Autowired
    private UserCache userCache;
    @Autowired
    private RealmProvider realmProvider;

    protected void deleteInvalidUser(final RealmModel realm, final UserModel user) {
        String userId = user.getId();
        String userName = user.getUsername();
        if (userCache != null) {
            userCache.evict(realm, user);
        }

        RealmModel realmModel = realmProvider.getRealm(realm.getId());
        if (realmModel == null) return;
        UserModel deletedUser = userProvider.getUserById(userId, realmModel);
        if (deletedUser != null) {
            new UserManager().removeUser(realmModel, deletedUser);
            LOG.debug("Removed invalid user '{}'", userName);
        }
    }


    protected List<UserModel> importValidation(RealmModel realm, List<UserModel> users) {
        List<UserModel> tmp = new LinkedList<>();
        for (UserModel user : users) {
            UserModel model = importValidation(realm, user);
            if (model == null) continue;
            tmp.add(model);
        }
        return tmp;
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        if (storageId.getProviderId() == null) {
            UserModel user = localStorage().getUserById(id, realm);
            return importValidation(realm, user);
        }
        UserLookupProvider provider = (UserLookupProvider) getStorageProvider(realm, storageId.getProviderId());
        if (provider == null) return null;
        if (!isStorageProviderEnabled(realm, storageId.getProviderId())) return null;
        return provider.getUserById(id, realm);
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return getGroupMembers(realm, group, -1, -1);
    }

    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role) {
        return getRoleMembers(realm, role, -1, -1);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        UserModel user = localStorage().getUserByUsername(username, realm);
        if (user != null) {
            return importValidation(realm, user);
        }
        for (UserLookupProvider provider : getEnabledStorageProviders(realm, UserLookupProvider.class)) {
            user = provider.getUserByUsername(username, realm);
            if (user != null) return user;
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        UserModel user = localStorage().getUserByEmail(email, realm);
        if (user != null) {
            return importValidation(realm, user);
        }
        for (UserLookupProvider provider : getEnabledStorageProviders(realm, UserLookupProvider.class)) {
            user = provider.getUserByEmail(email, realm);
            if (user != null) {
                return user;
            }
        }
        return null;
    }

    @Override
    public UserModel getUserByFederatedIdentity(FederatedIdentityModel socialLink, RealmModel realm) {
        UserModel user = localStorage().getUserByFederatedIdentity(socialLink, realm);
        if (user != null) {
            return importValidation(realm, user);
        }
        if (getFederatedStorage() == null) return null;
        String id = getFederatedStorage().getUserByFederatedIdentity(socialLink, realm);
        if (id != null) return getUserById(id, realm);
        return null;
    }

    @Override
    public UserModel getServiceAccount(ClientModel client) {
        return localStorage().getServiceAccount(client);
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, boolean includeServiceAccounts) {
        return getUsers(realm, 0, Integer.MAX_VALUE - 1, includeServiceAccounts);

    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return getUsers(realm, false);
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        return getUsers(realm, firstResult, maxResults, false);
    }

    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        int size = localStorage().getUsersCount(realm, includeServiceAccount);
        for (UserQueryProvider provider : getEnabledStorageProviders(realm, UserQueryProvider.class)) {
            size += provider.getUsersCount(realm);
        }
        return size;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return getUsersCount(realm, false);
    }

    @Override
    public int getUsersCount(RealmModel realm, Set<String> groupIds) {
        return localStorage().getUsersCount(realm, groupIds);
    }

    @Override
    public int getUsersCount(String search, RealmModel realm) {
        return localStorage().getUsersCount(search, realm);
    }

    @Override
    public int getUsersCount(String search, RealmModel realm, Set<String> groupIds) {
        return localStorage().getUsersCount(search, realm, groupIds);
    }

    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm) {
        return localStorage().getUsersCount(params, realm);
    }

    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm, Set<String> groupIds) {
        return localStorage().getUsersCount(params, realm, groupIds);
    }

    protected List<UserModel> query(PaginatedQuery pagedQuery, RealmModel realm, int firstResult, int maxResults) {
        if (maxResults == 0) return Collections.EMPTY_LIST;
        if (firstResult < 0) firstResult = 0;
        if (maxResults < 0) maxResults = Integer.MAX_VALUE - 1;

        List<UserQueryProvider> storageProviders = getEnabledStorageProviders(realm, UserQueryProvider.class);
        // we can skip rest of method if there are no storage providers
        if (storageProviders.isEmpty()) {
            return pagedQuery.query(localStorage(), firstResult, maxResults);
        }
        LinkedList<Object> providers = new LinkedList<>();
        List<UserModel> results = new LinkedList<UserModel>();
        providers.add(localStorage());
        providers.addAll(storageProviders);
        if (getFederatedStorage() != null) providers.add(getFederatedStorage());

        int leftToRead = maxResults;
        int leftToFirstResult = firstResult;

        Iterator<Object> it = providers.iterator();
        while (it.hasNext() && leftToRead != 0) {
            Object provider = it.next();
            boolean exhausted = false;
            int index = 0;
            if (leftToFirstResult > 0) {
                do {
                    int toRead = Math.min(50, leftToFirstResult);
                    List<UserModel> tmp = pagedQuery.query(provider, index, toRead);
                    leftToFirstResult -= tmp.size();
                    index += tmp.size();
                    if (tmp.size() < toRead) {
                        exhausted = true;
                        break;
                    }
                } while (leftToFirstResult > 0);
            }
            if (exhausted) continue;
            List<UserModel> tmp = pagedQuery.query(provider, index, leftToRead);
            results.addAll(tmp);
            if (leftToRead > 0) leftToRead -= tmp.size();
        }

        return results;
    }

    @Override
    public List<UserModel> getUsers(final RealmModel realm, int firstResult, int maxResults, final boolean includeServiceAccounts) {
        List<UserModel> results = query((provider, first, max) -> {
                    if (provider instanceof UserProvider) { // it is local storage
                        return ((UserProvider) provider).getUsers(realm, first, max, includeServiceAccounts);
                    } else if (provider instanceof UserQueryProvider) {
                        return ((UserQueryProvider) provider).getUsers(realm, first, max);

                    }
                    return Collections.EMPTY_LIST;
                }
                , realm, firstResult, maxResults);
        return importValidation(realm, results);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search, realm, 0, Integer.MAX_VALUE - 1);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        List<UserModel> results = query((provider, first, max) -> {
            if (provider instanceof UserQueryProvider) {
                return ((UserQueryProvider) provider).searchForUser(search, realm, first, max);

            }
            return Collections.EMPTY_LIST;
        }, realm, firstResult, maxResults);
        return importValidation(realm, results);

    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> attributes, RealmModel realm) {
        List<UserModel> results = searchForUser(attributes, realm, 0, Integer.MAX_VALUE - 1);
        return importValidation(realm, results);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> attributes, RealmModel realm, int firstResult, int maxResults) {
        List<UserModel> results = query((provider, first, max) -> {
                    if (provider instanceof UserQueryProvider) {
                        return ((UserQueryProvider) provider).searchForUser(attributes, realm, first, max);

                    }
                    return Collections.EMPTY_LIST;
                }
                , realm, firstResult, maxResults);
        return importValidation(realm, results);

    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        List<UserModel> results = query((provider, first, max) -> {
            if (provider instanceof UserQueryProvider) {
                return ((UserQueryProvider) provider).searchForUserByUserAttribute(attrName, attrValue, realm);

            } else if (provider instanceof UserFederatedStorageProvider) {
                List<String> ids = ((UserFederatedStorageProvider) provider).getUsersByUserAttribute(realm, attrName, attrValue);
                List<UserModel> rs = new LinkedList<>();
                for (String id : ids) {
                    UserModel user = getUserById(id, realm);
                    if (user != null) rs.add(user);
                }
                return rs;

            }
            return Collections.EMPTY_LIST;
        }, realm, 0, Integer.MAX_VALUE - 1);
        return importValidation(realm, results);
    }

    @Override
    public Set<FederatedIdentityModel> getFederatedIdentities(UserModel user, RealmModel realm) {
        if (user == null) throw new IllegalStateException("Federated user no longer valid");
        Set<FederatedIdentityModel> set = new HashSet<>();
        if (StorageId.isLocalStorage(user)) {
            set.addAll(localStorage().getFederatedIdentities(user, realm));
        }
        if (getFederatedStorage() != null)
            set.addAll(getFederatedStorage().getFederatedIdentities(user.getId(), realm));
        return set;
    }

    @Override
    public FederatedIdentityModel getFederatedIdentity(UserModel user, String socialProvider, RealmModel realm) {
        if (user == null) throw new IllegalStateException("Federated user no longer valid");
        if (StorageId.isLocalStorage(user)) {
            FederatedIdentityModel model = localStorage().getFederatedIdentity(user, socialProvider, realm);
            if (model != null) return model;
        }
        if (getFederatedStorage() != null)
            return getFederatedStorage().getFederatedIdentity(user.getId(), socialProvider, realm);
        else return null;
    }

    @Override
    public void grantToAllUsers(RealmModel realm, RoleModel role) {
        List<UserBulkUpdateProvider> storageProviders = getEnabledStorageProviders(realm, UserBulkUpdateProvider.class);
        LinkedList<UserBulkUpdateProvider> providers = new LinkedList<>();
        providers.add(localStorage());
        providers.addAll(storageProviders);
        for (UserBulkUpdateProvider provider : providers) {
            provider.grantToAllUsers(realm, role);
        }
    }

    @Override
    public List<UserModel> getGroupMembers(final RealmModel realm, final GroupModel group, int firstResult, int maxResults) {
        List<UserModel> results = query((provider, first, max) -> {
            if (provider instanceof UserQueryProvider) {
                return ((UserQueryProvider) provider).getGroupMembers(realm, group, first, max);

            } else if (provider instanceof UserFederatedStorageProvider) {
                List<String> ids = ((UserFederatedStorageProvider) provider).getMembership(realm, group, first, max);
                List<UserModel> rs = new LinkedList<UserModel>();
                for (String id : ids) {
                    UserModel user = getUserById(id, realm);
                    if (user != null) rs.add(user);
                }
                return rs;

            }
            return Collections.EMPTY_LIST;
        }, realm, firstResult, maxResults);
        return importValidation(realm, results);
    }

    @Override
    public List<UserModel> getRoleMembers(final RealmModel realm, final RoleModel role, int firstResult, int maxResults) {
        List<UserModel> results = query((provider, first, max) -> {
            if (provider instanceof UserQueryProvider) {
                return ((UserQueryProvider) provider).getRoleMembers(realm, role, first, max);
            }
            return Collections.EMPTY_LIST;
        }, realm, firstResult, maxResults);
        return importValidation(realm, results);
    }

    @Override
    public void preRemove(RealmModel realm) {
        localStorage().preRemove(realm);
        if (getFederatedStorage() != null) {
            getFederatedStorage().preRemove(realm);
            for (UserStorageProvider provider : getEnabledStorageProviders(realm, UserStorageProvider.class)) {
                provider.preRemove(realm);
            }
        }
    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        localStorage().preRemove(realm, group);
        if (getFederatedStorage() != null) {
            getFederatedStorage().preRemove(realm, group);
            for (UserStorageProvider provider : getEnabledStorageProviders(realm, UserStorageProvider.class)) {
                provider.preRemove(realm, group);
            }
        }
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        localStorage().preRemove(realm, role);
        if (getFederatedStorage() != null) {
            getFederatedStorage().preRemove(realm, role);
            for (UserStorageProvider provider : getEnabledStorageProviders(realm, UserStorageProvider.class)) {
                provider.preRemove(realm, role);
            }
        }
    }

    @Override
    public void preRemove(RealmModel realm, ClientModel client) {
        localStorage().preRemove(realm, client);
        if (getFederatedStorage() != null) getFederatedStorage().preRemove(realm, client);

    }

    @Override
    public void preRemove(ProtocolMapperModel protocolMapper) {
        localStorage().preRemove(protocolMapper);
        if (getFederatedStorage() != null) getFederatedStorage().preRemove(protocolMapper);
    }

    @Override
    public void preRemove(ClientScopeModel clientScope) {
        localStorage().preRemove(clientScope);
        if (getFederatedStorage() != null) getFederatedStorage().preRemove(clientScope);
    }

    @Override
    public void preRemove(RealmModel realm, ComponentModel component) {
        if (component.getProviderType().equals(ClientStorageProvider.class.getName())) {
            localStorage().preRemove(realm, component);
            if (getFederatedStorage() != null) getFederatedStorage().preRemove(realm, component);
            return;
        }
        if (!component.getProviderType().equals(UserStorageProvider.class.getName())) return;
        localStorage().preRemove(realm, component);
        if (getFederatedStorage() != null) getFederatedStorage().preRemove(realm, component);
        new UserStorageSyncManager().notifyToRefreshPeriodicSync(realm, new UserStorageProviderModel(component), true);

    }

    @Override
    public void removeImportedUsers(RealmModel realm, String storageProviderId) {
        localStorage().removeImportedUsers(realm, storageProviderId);
    }

    @Override
    public void unlinkUsers(RealmModel realm, String storageProviderId) {
        localStorage().unlinkUsers(realm, storageProviderId);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        if (StorageId.isLocalStorage(user)) {
            if (userProvider instanceof OnUserCache) {
                ((OnUserCache) userProvider).onCache(realm, user, delegate);
            }
        } else {
            Object provider = getStorageProvider(realm, StorageId.resolveProviderId(user));
            if (provider instanceof OnUserCache) {
                ((OnUserCache) provider).onCache(realm, user, delegate);
            }
        }
    }

    @Override
    public void close() {
    }

    @Override
    public void onCreate(RealmModel realm, ComponentModel model) {
        ComponentFactory factory = componentUtil.getComponentFactory(model);
        if (!(factory instanceof UserStorageProviderFactory)) return;
        new UserStorageSyncManager().notifyToRefreshPeriodicSync(realm, new UserStorageProviderModel(model), false);

    }

    @Autowired
    private ComponentUtil componentUtil;

    @Override
    public void onUpdate(RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        ComponentFactory factory = componentUtil.getComponentFactory(newModel);
        if (!(factory instanceof UserStorageProviderFactory)) return;
        UserStorageProviderModel old = new UserStorageProviderModel(oldModel);
        UserStorageProviderModel newP = new UserStorageProviderModel(newModel);
        if (old.getChangedSyncPeriod() != newP.getChangedSyncPeriod() || old.getFullSyncPeriod() != newP.getFullSyncPeriod()
                || old.isImportEnabled() != newP.isImportEnabled()) {
            new UserStorageSyncManager().notifyToRefreshPeriodicSync(realm, new UserStorageProviderModel(newModel), false);
        }

    }

    @FunctionalInterface
    interface PaginatedQuery {
        List<UserModel> query(Object provider, int first, int max);
    }
}
