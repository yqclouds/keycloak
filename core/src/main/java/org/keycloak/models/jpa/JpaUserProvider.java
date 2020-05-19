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

package org.keycloak.models.jpa;

import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.repository.*;
import org.keycloak.authorization.jpa.entities.Resource;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.*;
import org.keycloak.models.utils.DefaultRoles;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.client.ClientStorageProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.LockModeType;
import javax.persistence.criteria.Expression;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import javax.persistence.criteria.Subquery;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@SuppressWarnings("JpaQueryApiInspection")
public class JpaUserProvider implements UserProvider, UserCredentialStore {

    private static final String EMAIL = "email";
    private static final String USERNAME = "username";
    private static final String FIRST_NAME = "firstName";
    private static final String LAST_NAME = "lastName";

    private final KeycloakSession session;
    private final JpaUserCredentialStore credentialStore;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserRoleMappingRepository userRoleMappingRepository;
    @Autowired
    private UserGroupMembershipRepository userGroupMembershipRepository;
    @Autowired
    private FederatedIdentityRepository federatedIdentityRepository;
    @Autowired
    private UserConsentRepository userConsentRepository;
    @Autowired
    private UserConsentClientScopeRepository userConsentClientScopeRepository;
    @Autowired
    private UserRequiredActionRepository userRequiredActionRepository;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private UserAttributeRepository userAttributeRepository;

    public JpaUserProvider(KeycloakSession session) {
        this.session = session;
        credentialStore = new JpaUserCredentialStore();
    }

    @Override
    public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        if (id == null) {
            id = KeycloakModelUtils.generateId();
        }

        User entity = new User();
        entity.setId(id);
        entity.setCreatedTimestamp(System.currentTimeMillis());
        entity.setUsername(username.toLowerCase());
        entity.setRealmId(realm.getId());
        userRepository.saveAndFlush(entity);

        UserAdapter userModel = new UserAdapter(realm, entity);
        if (addDefaultRoles) {
            DefaultRoles.addDefaultRoles(realm, userModel);

            for (GroupModel g : realm.getDefaultGroups()) {
                userModel.joinGroupImpl(g); // No need to check if user has group as it's new user
            }
        }

        if (addDefaultRequiredActions) {
            for (RequiredActionProviderModel r : realm.getRequiredActionProviders()) {
                if (r.isEnabled() && r.isDefaultAction()) {
                    userModel.addRequiredAction(r.getAlias());
                }
            }
        }

        return userModel;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        return addUser(realm, KeycloakModelUtils.generateId(), username.toLowerCase(), true, true);
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        Optional<User> optional = userRepository.findById(user.getId());
        if (!optional.isPresent()) return false;
        removeUser(optional.get());
        return true;
    }

    private void removeUser(User user) {
        userRoleMappingRepository.deleteUserRoleMappingsByUser(user);
        userGroupMembershipRepository.deleteUserGroupMembershipsByUser(user);
        federatedIdentityRepository.deleteFederatedIdentityByUser(user);
        userConsentClientScopeRepository.deleteUserConsentClientScopesByUser(user);
        userConsentRepository.deleteUserConsentsByUser(user);
        userRepository.delete(user);
    }

    @Override
    public void addFederatedIdentity(RealmModel realm, UserModel user, FederatedIdentityModel identity) {
        FederatedIdentity entity = new FederatedIdentity();
        entity.setRealmId(realm.getId());
        entity.setIdentityProvider(identity.getIdentityProvider());
        entity.setUserId(identity.getUserId());
        entity.setUserName(identity.getUserName().toLowerCase());
        entity.setToken(identity.getToken());
        User userEntity = userRepository.getOne(user.getId());
        entity.setUser(userEntity);
        federatedIdentityRepository.save(entity);
    }

    @Override
    public void updateFederatedIdentity(RealmModel realm, UserModel federatedUser, FederatedIdentityModel federatedIdentityModel) {
        FederatedIdentity federatedIdentity = findFederatedIdentity(federatedUser, federatedIdentityModel.getIdentityProvider(), LockModeType.PESSIMISTIC_WRITE);
        federatedIdentity.setToken(federatedIdentityModel.getToken());
        federatedIdentityRepository.save(federatedIdentity);
    }

    @Override
    public boolean removeFederatedIdentity(RealmModel realm, UserModel user, String identityProvider) {
        FederatedIdentity entity = findFederatedIdentity(user, identityProvider, LockModeType.PESSIMISTIC_WRITE);
        if (entity != null) {
            federatedIdentityRepository.delete(entity);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void addConsent(RealmModel realm, String userId, UserConsentModel consent) {
        String clientId = consent.getClient().getId();

        UserConsent consentEntity = getGrantedConsentEntity(userId, clientId, LockModeType.NONE);
        if (consentEntity != null) {
            throw new ModelDuplicateException("Consent already exists for client [" + clientId + "] and user [" + userId + "]");
        }

        long currentTime = Time.currentTimeMillis();

        consentEntity = new UserConsent();
        consentEntity.setId(KeycloakModelUtils.generateId());
        consentEntity.setUser(userRepository.getOne(userId));
        StorageId clientStorageId = new StorageId(clientId);
        if (clientStorageId.isLocal()) {
            consentEntity.setClientId(clientId);
        } else {
            consentEntity.setClientStorageProvider(clientStorageId.getProviderId());
            consentEntity.setExternalClientId(clientStorageId.getExternalId());
        }

        consentEntity.setCreatedDate(currentTime);
        consentEntity.setLastUpdatedDate(currentTime);
        userConsentRepository.save(consentEntity);
        updateGrantedConsentEntity(consentEntity, consent);
    }

    @Override
    public UserConsentModel getConsentByClient(RealmModel realm, String userId, String clientId) {
        UserConsent entity = getGrantedConsentEntity(userId, clientId, LockModeType.NONE);
        return toConsentModel(realm, entity);
    }

    @Override
    public List<UserConsentModel> getConsents(RealmModel realm, String userId) {
        List<UserConsent> results = userConsentRepository.userConsentsByUser(userId);
        List<UserConsentModel> consents = new ArrayList<>();
        for (UserConsent entity : results) {
            UserConsentModel model = toConsentModel(realm, entity);
            consents.add(model);
        }
        return consents;
    }

    @Override
    public void updateConsent(RealmModel realm, String userId, UserConsentModel consent) {
        String clientId = consent.getClient().getId();

        UserConsent consentEntity = getGrantedConsentEntity(userId, clientId, LockModeType.PESSIMISTIC_WRITE);
        if (consentEntity == null) {
            throw new ModelException("Consent not found for client [" + clientId + "] and user [" + userId + "]");
        }

        updateGrantedConsentEntity(consentEntity, consent);
    }

    public boolean revokeConsentForClient(RealmModel realm, String userId, String clientId) {
        UserConsent consentEntity = getGrantedConsentEntity(userId, clientId, LockModeType.PESSIMISTIC_WRITE);
        if (consentEntity == null) return false;
        userConsentRepository.delete(consentEntity);
        return true;
    }

    private UserConsent getGrantedConsentEntity(String userId, String clientId, LockModeType lockMode) {
        StorageId clientStorageId = new StorageId(clientId);

        List<UserConsent> results;
        if (clientStorageId.isLocal()) {
            results = userConsentRepository.userConsentByUserAndClient(userId, clientId);
        } else {
            results = userConsentRepository.userConsentByUserAndExternalClient(userId, clientStorageId.getProviderId(), clientStorageId.getExternalId());
        }
        if (results.size() > 1) {
            throw new ModelException("More results found for user [" + userId + "] and client [" + clientId + "]");
        } else if (results.size() == 1) {
            return results.get(0);
        }

        return null;
    }

    private UserConsentModel toConsentModel(RealmModel realm, UserConsent entity) {
        if (entity == null) {
            return null;
        }

        StorageId clientStorageId;
        if (entity.getClientId() == null) {
            clientStorageId = new StorageId(entity.getClientStorageProvider(), entity.getExternalClientId());
        } else {
            clientStorageId = new StorageId(entity.getClientId());
        }

        ClientModel client = realm.getClientById(clientStorageId.getId());
        if (client == null) {
            throw new ModelException("Client with id " + clientStorageId.getId() + " is not available");
        }
        UserConsentModel model = new UserConsentModel(client);
        model.setCreatedDate(entity.getCreatedDate());
        model.setLastUpdatedDate(entity.getLastUpdatedDate());

        Collection<UserConsentClientScope> grantedClientScopeEntities = entity.getGrantedClientScopes();
        if (grantedClientScopeEntities != null) {
            for (UserConsentClientScope grantedClientScope : grantedClientScopeEntities) {
                ClientScopeModel grantedClientScopeModel = KeycloakModelUtils.findClientScopeById(realm, client, grantedClientScope.getScopeId());
                if (grantedClientScopeModel != null) {
                    model.addGrantedClientScope(grantedClientScopeModel);
                }
            }
        }

        return model;
    }

    // Update roles and protocolMappers to given consentEntity from the consentModel
    private void updateGrantedConsentEntity(UserConsent consentEntity, UserConsentModel consentModel) {
        Collection<UserConsentClientScope> grantedClientScopeEntities = consentEntity.getGrantedClientScopes();
        Collection<UserConsentClientScope> scopesToRemove = new HashSet<>(grantedClientScopeEntities);

        for (ClientScopeModel clientScope : consentModel.getGrantedClientScopes()) {
            UserConsentClientScope grantedClientScopeEntity = new UserConsentClientScope();
            grantedClientScopeEntity.setUserConsent(consentEntity);
            grantedClientScopeEntity.setScopeId(clientScope.getId());

            // Check if it's already there
            if (!grantedClientScopeEntities.contains(grantedClientScopeEntity)) {
                userConsentClientScopeRepository.save(grantedClientScopeEntity);
                grantedClientScopeEntities.add(grantedClientScopeEntity);
            } else {
                scopesToRemove.remove(grantedClientScopeEntity);
            }
        }
        // Those client scopes were no longer on consentModel and will be removed
        for (UserConsentClientScope toRemove : scopesToRemove) {
            grantedClientScopeEntities.remove(toRemove);
            userConsentClientScopeRepository.delete(toRemove);
        }

        consentEntity.setLastUpdatedDate(Time.currentTimeMillis());
        userConsentRepository.save(consentEntity);
    }

    @Override
    public void setNotBeforeForUser(RealmModel realm, UserModel user, int notBefore) {
        User entity = userRepository.getOne(user.getId());
        entity.setNotBefore(notBefore);
    }

    @Override
    public int getNotBeforeOfUser(RealmModel realm, UserModel user) {
        User entity = userRepository.getOne(user.getId());
        return entity.getNotBefore();
    }

    @Override
    public void grantToAllUsers(RealmModel realm, RoleModel role) {
        userRoleMappingRepository.grantRoleToAllUsers(realm.getId(), role.getId());
    }

    @Override
    public void preRemove(RealmModel realm) {
        userConsentClientScopeRepository.deleteUserConsentClientScopesByRealm(realm.getId());
        userConsentRepository.deleteUserConsentsByRealm(realm.getId());
        userRoleMappingRepository.deleteUserRoleMappingsByRealm(realm.getId());
        userRequiredActionRepository.deleteUserRequiredActionsByRealm(realm.getId());
        federatedIdentityRepository.deleteFederatedIdentityByRealm(realm.getId());
        credentialRepository.deleteCredentialsByRealm(realm.getId());
        userAttributeRepository.deleteUserAttributesByRealm(realm.getId());
        userGroupMembershipRepository.deleteUserGroupMembershipByRealm(realm.getId());
        userRepository.deleteUsersByRealm(realm.getId());
    }

    @Override
    public void removeImportedUsers(RealmModel realm, String storageProviderId) {
        userRoleMappingRepository.deleteUserRoleMappingsByRealmAndLink(realm.getId(), storageProviderId);
        userRequiredActionRepository.deleteUserRequiredActionsByRealmAndLink(realm.getId(), storageProviderId);
        federatedIdentityRepository.deleteFederatedIdentityByRealmAndLink(realm.getId(), storageProviderId);
        credentialRepository.deleteCredentialsByRealmAndLink(realm.getId(), storageProviderId);
        userAttributeRepository.deleteUserAttributesByRealmAndLink(realm.getId(), storageProviderId);
        userGroupMembershipRepository.deleteUserGroupMembershipsByRealmAndLink(realm.getId(), storageProviderId);
        userConsentClientScopeRepository.deleteUserConsentClientScopesByRealmAndLink(realm.getId(), storageProviderId);
        userConsentRepository.deleteUserConsentsByRealmAndLink(realm.getId(), storageProviderId);
        userRepository.deleteUsersByRealmAndLink(realm.getId(), storageProviderId);
    }

    @Override
    public void unlinkUsers(RealmModel realm, String storageProviderId) {
        userRepository.unlinkUsers(realm.getId(), storageProviderId);
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        userRoleMappingRepository.deleteUserRoleMappingsByRole(role.getId());
    }

    @Override
    public void preRemove(RealmModel realm, ClientModel client) {
        StorageId clientStorageId = new StorageId(client.getId());
        if (clientStorageId.isLocal()) {
            userConsentClientScopeRepository.deleteUserConsentClientScopesByClient(client.getId());
            userConsentRepository.deleteUserConsentsByClient(client.getId());
        } else {
            userConsentClientScopeRepository.deleteUserConsentClientScopesByExternalClient(clientStorageId.getProviderId(), clientStorageId.getExternalId());
            userConsentRepository.deleteUserConsentsByExternalClient(clientStorageId.getProviderId(), clientStorageId.getExternalId());
        }
    }

    @Override
    public void preRemove(ProtocolMapperModel protocolMapper) {
        // No-op
    }

    @Override
    public void preRemove(ClientScopeModel clientScope) {
        userConsentClientScopeRepository.deleteUserConsentClientScopesByClientScope(clientScope.getId());
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        List<User> results = userGroupMembershipRepository.groupMembership(group.getId());
        List<UserModel> users = new ArrayList<>();
        for (User user : results) {
            users.add(new UserAdapter(realm, user));
        }
        return users;
    }

    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role) {
        List<User> results = userRoleMappingRepository.usersInRole(role.getId());
        List<UserModel> users = new ArrayList<>();
        for (User user : results) {
            users.add(new UserAdapter(realm, user));
        }
        return users;
    }


    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        userGroupMembershipRepository.deleteUserGroupMembershipsByGroup(group.getId());
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        Optional<User> optional = userRepository.findById(id);
        if (!optional.isPresent() || !realm.getId().equals(optional.get().getRealmId())) return null;
        return new UserAdapter(realm, optional.get());
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        List<User> results = userRepository.getRealmUserByUsername(username.toLowerCase(), realm.getId());
        if (results.size() == 0) return null;
        return new UserAdapter(realm, results.get(0));
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        List<User> results = userRepository.getRealmUserByEmail(email.toLowerCase(), realm.getId());

        if (results.isEmpty()) return null;

        ensureEmailConstraint(results, realm);

        return new UserAdapter(realm, results.get(0));
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserByFederatedIdentity(FederatedIdentityModel identity, RealmModel realm) {
        List<User> results = federatedIdentityRepository.findUserByFederatedIdentityAndRealm(realm.getId(), identity.getUserId(), identity.getIdentityProvider());
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More results found for identityProvider=" + identity.getIdentityProvider() +
                    ", userId=" + identity.getUserId() + ", results=" + results);
        } else {
            User user = results.get(0);
            return new UserAdapter(realm, user);
        }
    }

    @Override
    public UserModel getServiceAccount(ClientModel client) {
        List<User> results = userRepository.getRealmUserByServiceAccount(client.getRealm().getId(), client.getId());
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More service account linked users found for client=" + client.getClientId() +
                    ", results=" + results);
        } else {
            User user = results.get(0);
            return new UserAdapter(client.getRealm(), user);
        }
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, boolean includeServiceAccounts) {
        return getUsers(realm, -1, -1, includeServiceAccounts);
    }

    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        Integer count;
        if (includeServiceAccount) {
            count = userRepository.getRealmUserCount(realm.getId());
        } else {
            count = userRepository.getRealmUserCountExcludeServiceAccount(realm.getId());
        }

        return count;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return getUsersCount(realm, false);
    }

    @Override
    public int getUsersCount(RealmModel realm, Set<String> groupIds) {
        if (groupIds == null || groupIds.isEmpty()) {
            return 0;
        }

        Long count = userGroupMembershipRepository.userCountInGroups(realm.getId(), groupIds);
        return count.intValue();
    }

    @Override
    public int getUsersCount(String search, RealmModel realm) {
        Long count = userRepository.searchForUserCount(realm.getId(), "%" + search.toLowerCase() + "%");
        return count.intValue();
    }

    @Override
    public int getUsersCount(String search, RealmModel realm, Set<String> groupIds) {
        if (groupIds == null || groupIds.isEmpty()) {
            return 0;
        }

        Long count = userGroupMembershipRepository.searchForUserCountInGroups(realm.getId(), groupIds, "%" + search.toLowerCase() + "%");
        return count.intValue();
    }

    private static Specification<User> getUsersCountSpecification(Map<String, String> params, RealmModel realm) {
        return (Specification<User>) (root, query, cb) -> {
            List<Predicate> restrictions = new ArrayList<>();
            restrictions.add(cb.equal(root.get("realmId"), realm.getId()));
            for (Map.Entry<String, String> entry : params.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                if (key == null || value == null) {
                    continue;
                }

                switch (key) {
                    case UserModel.USERNAME:
                        restrictions.add(cb.like(root.get("username"), "%" + value + "%"));
                        break;
                    case UserModel.FIRST_NAME:
                        restrictions.add(cb.like(root.get("firstName"), "%" + value + "%"));
                        break;
                    case UserModel.LAST_NAME:
                        restrictions.add(cb.like(root.get("lastName"), "%" + value + "%"));
                        break;
                    case UserModel.EMAIL:
                        restrictions.add(cb.like(root.get("email"), "%" + value + "%"));
                        break;
                }
            }

            return cb.and(restrictions.toArray(new Predicate[0]));
        };
    }

    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm) {
        List<User> results = userRepository.findAll(getUsersCountSpecification(params, realm));
        return results.size();
    }

    private static Specification<UserGroupMembership> getUsersCountSpecification(Map<String, String> params, RealmModel realm, Set<String> groupIds) {
        return (Specification<UserGroupMembership>) (root, query, cb) -> {
            List<Predicate> restrictions = new ArrayList<>();
            restrictions.add(cb.equal(root.get("user").get("realmId"), realm.getId()));
            restrictions.add(root.get("groupId").in(groupIds));

            for (Map.Entry<String, String> entry : params.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                if (key == null || value == null) {
                    continue;
                }

                switch (key) {
                    case UserModel.USERNAME:
                        restrictions.add(cb.like(root.get("user").get("username"), "%" + value + "%"));
                        break;
                    case UserModel.FIRST_NAME:
                        restrictions.add(cb.like(root.get("user").get("firstName"), "%" + value + "%"));
                        break;
                    case UserModel.LAST_NAME:
                        restrictions.add(cb.like(root.get("user").get("lastName"), "%" + value + "%"));
                        break;
                    case UserModel.EMAIL:
                        restrictions.add(cb.like(root.get("user").get("email"), "%" + value + "%"));
                        break;
                }
            }

            return cb.and(restrictions.toArray(new Predicate[0]));
        };
    }

    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm, Set<String> groupIds) {
        if (groupIds == null || groupIds.isEmpty()) {
            return 0;
        }

        List<UserGroupMembership> results = userGroupMembershipRepository.findAll(getUsersCountSpecification(params, realm, groupIds));
        return results.size();
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
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults, boolean includeServiceAccounts) {
        List<User> results;
        if (includeServiceAccounts) {
            results = userRepository.getAllUsersByRealm(realm.getId());
        } else {
            results = userRepository.getAllUsersByRealmExcludeServiceAccount(realm.getId());
        }
        List<UserModel> users = new LinkedList<>();
        for (User entity : results) users.add(new UserAdapter(realm, entity));
        return users;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        List<User> results = userGroupMembershipRepository.groupMembership(group.getId());
        List<UserModel> users = new LinkedList<>();
        for (User user : results) {
            users.add(new UserAdapter(realm, user));
        }
        return users;
    }

    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role, int firstResult, int maxResults) {
        List<User> results = userRoleMappingRepository.usersInRole(role.getId());
        List<UserModel> users = new LinkedList<>();
        for (User user : results) {
            users.add(new UserAdapter(realm, user));
        }
        return users;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search, realm, -1, -1);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        List<User> results = userRepository.searchForUser(realm.getId(), "%" + search.toLowerCase() + "%");
        List<UserModel> users = new LinkedList<>();
        for (User entity : results) users.add(new UserAdapter(realm, entity));
        return users;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> attributes, RealmModel realm) {
        return searchForUser(attributes, realm, -1, -1);
    }

    private static Specification<User> searchForUserSpecification(KeycloakSession session, Map<String, String> attributes, RealmModel realm) {
        return (Specification<User>) (root, query, cb) -> {
            List<Predicate> restrictions = new ArrayList<>();

            restrictions.add(cb.equal(root.get("realmId"), realm.getId()));

            if (!session.getAttributeOrDefault(UserModel.INCLUDE_SERVICE_ACCOUNT, true)) {
                restrictions.add(root.get("serviceAccountClientLink").isNull());
            }

            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                if (value == null) {
                    continue;
                }

                switch (key) {
                    case UserModel.SEARCH:
                        List<Predicate> orPredicates = new ArrayList<>();

                        orPredicates.add(cb.like(cb.lower(root.get(UserModel.USERNAME)), "%" + value.toLowerCase() + "%"));
                        orPredicates.add(cb.like(cb.lower(root.get(UserModel.EMAIL)), "%" + value.toLowerCase() + "%"));
                        orPredicates.add(cb.like(
                                cb.lower(cb.concat(cb.concat(
                                        cb.coalesce(root.get(UserModel.FIRST_NAME), cb.literal("")), " "),
                                        cb.coalesce(root.get(UserModel.LAST_NAME), cb.literal("")))),
                                "%" + value.toLowerCase() + "%"));

                        restrictions.add(cb.or(orPredicates.toArray(new Predicate[orPredicates.size()])));

                        break;

                    case UserModel.USERNAME:
                    case UserModel.FIRST_NAME:
                    case UserModel.LAST_NAME:
                    case UserModel.EMAIL:
                        restrictions.add(cb.like(cb.lower(root.get(key)), "%" + value.toLowerCase() + "%"));
                }
            }

            Set<String> userGroups = (Set<String>) session.getAttribute(UserModel.GROUPS);

            if (userGroups != null) {
                Subquery subquery = query.subquery(String.class);
                Root<UserGroupMembership> from = subquery.from(UserGroupMembership.class);

                subquery.select(cb.literal(1));

                List<Predicate> subPredicates = new ArrayList<>();

                subPredicates.add(from.get("groupId").in(userGroups));
                subPredicates.add(cb.equal(from.get("user").get("id"), root.get("id")));

                Subquery subquery1 = query.subquery(String.class);

                subquery1.select(cb.literal(1));
                Root from1 = subquery1.from(Resource.class);

                List<Predicate> subs = new ArrayList<>();

                Expression<String> groupId = from.get("groupId");
                subs.add(cb.like(from1.get("name"), cb.concat("group.resource.", groupId)));

                subquery1.where(subs.toArray(new Predicate[0]));

                subPredicates.add(cb.exists(subquery1));

                subquery.where(subPredicates.toArray(new Predicate[0]));

                restrictions.add(cb.exists(subquery));
            }

            query.where(restrictions.toArray(new Predicate[0])).orderBy(cb.asc(root.get(UserModel.USERNAME)));

            return cb.and(restrictions.toArray(new Predicate[0]));
        };
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> attributes, RealmModel realm, int firstResult, int maxResults) {
        List<UserModel> results = new ArrayList<>();
        UserProvider users = session.users();

        for (User entity : userRepository.findAll(searchForUserSpecification(session, attributes, realm))) {
            results.add(users.getUserById(entity.getId(), realm));
        }

        return results;
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        List<User> results = userRepository.getRealmUsersByAttributeNameAndValue(realm.getId(), attrName, attrValue);
        List<UserModel> users = new ArrayList<>();
        for (User user : results) {
            users.add(new UserAdapter(realm, user));
        }
        return users;
    }

    private FederatedIdentity findFederatedIdentity(UserModel user, String identityProvider, LockModeType lockMode) {
        User userEntity = userRepository.getOne(user.getId());
        List<FederatedIdentity> results = federatedIdentityRepository.findFederatedIdentityByUserAndProvider(userEntity, identityProvider);
        return results.size() > 0 ? results.get(0) : null;
    }

    @Override
    public Set<FederatedIdentityModel> getFederatedIdentities(UserModel user, RealmModel realm) {
        User userEntity = userRepository.getOne(user.getId());
        List<FederatedIdentity> results = federatedIdentityRepository.findFederatedIdentityByUser(userEntity);
        Set<FederatedIdentityModel> set = new HashSet<>();
        for (FederatedIdentity entity : results) {
            set.add(new FederatedIdentityModel(entity.getIdentityProvider(), entity.getUserId(), entity.getUserName(), entity.getToken()));
        }
        return set;
    }

    @Override
    public FederatedIdentityModel getFederatedIdentity(UserModel user, String identityProvider, RealmModel realm) {
        FederatedIdentity entity = findFederatedIdentity(user, identityProvider, LockModeType.NONE);
        return (entity != null) ? new FederatedIdentityModel(entity.getIdentityProvider(), entity.getUserId(), entity.getUserName(), entity.getToken()) : null;
    }

    @Override
    public void preRemove(RealmModel realm, ComponentModel component) {
        if (component.getProviderType().equals(UserStorageProvider.class.getName())) {
            removeImportedUsers(realm, component.getId());
        }
        if (component.getProviderType().equals(ClientStorageProvider.class.getName())) {
            removeConsentByClientStorageProvider(realm, component.getId());
        }
    }

    protected void removeConsentByClientStorageProvider(RealmModel realm, String providerId) {
        userConsentClientScopeRepository.deleteUserConsentClientScopesByClientStorageProvider(providerId);
        userConsentRepository.deleteUserConsentsByClientStorageProvider(providerId);
    }

    @Override
    public void updateCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        credentialStore.updateCredential(realm, user, cred);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        Credential entity = credentialStore.createCredentialEntity(realm, user, cred);

        User userEntity = userRepository.getOne(user.getId());
        userEntity.getCredentials().add(entity);
        return toModel(entity);
    }

    @Override
    public boolean removeStoredCredential(RealmModel realm, UserModel user, String id) {
        Credential entity = credentialStore.removeCredentialEntity(realm, user, id);
        User userEntity = userRepository.getOne(user.getId());
        if (entity != null && userEntity != null) {
            userEntity.getCredentials().remove(entity);
        }
        return entity != null;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realm, UserModel user, String id) {
        return credentialStore.getStoredCredentialById(realm, user, id);
    }

    protected CredentialModel toModel(Credential entity) {
        return credentialStore.toModel(entity);
    }

    @Override
    public List<CredentialModel> getStoredCredentials(RealmModel realm, UserModel user) {
        return credentialStore.getStoredCredentials(realm, user);
    }

    @Override
    public List<CredentialModel> getStoredCredentialsByType(RealmModel realm, UserModel user, String type) {
        List<Credential> results;
        User userEntity = userRepository.getOne(user.getId());
        if (userEntity != null) {
            // user already in persistence context, no need to execute a query
            results = userEntity.getCredentials().stream().filter(it -> type.equals(it.getType()))
                    .sorted(Comparator.comparingInt(Credential::getPriority))
                    .collect(Collectors.toList());
            List<CredentialModel> rtn = new LinkedList<>();
            for (Credential entity : results) {
                rtn.add(toModel(entity));
            }
            return rtn;
        } else {
            return credentialStore.getStoredCredentialsByType(realm, user, type);
        }
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realm, UserModel user, String name, String type) {
        return credentialStore.getStoredCredentialByNameAndType(realm, user, name, type);
    }

    @Override
    public boolean moveCredentialTo(RealmModel realm, UserModel user, String id, String newPreviousCredentialId) {
        return credentialStore.moveCredentialTo(realm, user, id, newPreviousCredentialId);
    }

    // Could override this to provide a custom behavior.
    protected void ensureEmailConstraint(List<User> users, RealmModel realm) {
        User user = users.get(0);

        if (users.size() > 1) {
            // Realm settings have been changed from allowing duplicate emails to not allowing them
            // but duplicates haven't been removed.
            throw new ModelDuplicateException("Multiple users with email '" + user.getEmail() + "' exist in Keycloak.");
        }

        if (realm.isDuplicateEmailsAllowed()) {
            return;
        }

        if (user.getEmail() != null && !user.getEmail().equals(user.getEmailConstraint())) {
            // Realm settings have been changed from allowing duplicate emails to not allowing them.
            // We need to update the email constraint to reflect this change in the user entities.
            user.setEmailConstraint(user.getEmail());
            userRepository.saveAndFlush(user);
        }
    }
}
