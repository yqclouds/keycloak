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
package org.keycloak.storage.jpa;

import com.hsbc.unified.iam.core.util.Base64;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaUserCredentialStore;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.storage.jpa.entity.*;
import org.keycloak.storage.jpa.entity.FederatedUserRequiredAction.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JpaUserFederatedStorageProvider implements UserFederatedStorageProvider, UserCredentialStore {

    protected static final Logger LOG = LoggerFactory.getLogger(JpaUserFederatedStorageProvider.class);

    @Autowired
    private FederatedUserRepository federatedUserRepository;
    @Autowired
    private FederatedUserAttributeRepository federatedUserAttributeRepository;
    @Autowired
    private FederatedUserConsentRepository federatedUserConsentRepository;
    @Autowired
    private FederatedUserConsentClientScopeRepository federatedUserConsentClientScopeRepository;
    @Autowired
    private BrokerLinkRepository brokerLinkRepository;
    @Autowired
    private FederatedUserGroupMembershipRepository federatedUserGroupMembershipRepository;
    @Autowired
    private FederatedUserRequiredActionRepository federatedUserRequiredActionRepository;
    @Autowired
    private FederatedUserRoleMappingRepository federatedUserRoleMappingRepository;
    @Autowired
    private FederatedUserCredentialRepository federatedUserCredentialRepository;

    @Override
    public void close() {
    }

    /**
     * We create an entry so that its easy to iterate over all things in the database.  Specifically useful for export
     */
    protected void createIndex(RealmModel realm, String userId) {
        Optional<FederatedUser> optional = federatedUserRepository.findById(userId);
        if (!optional.isPresent()) {
            FederatedUser fedUser = new FederatedUser();
            fedUser.setId(userId);
            fedUser.setRealmId(realm.getId());
            fedUser.setStorageProviderId(new StorageId(userId).getProviderId());
            federatedUserRepository.save(fedUser);
        }
    }

    @Override
    public void setAttribute(RealmModel realm, String userId, String name, List<String> values) {
        createIndex(realm, userId);
        deleteAttribute(realm, userId, name);
        for (String value : values) {
            persistAttributeValue(realm, userId, name, value);
        }
    }

    private void deleteAttribute(RealmModel realm, String userId, String name) {
        federatedUserAttributeRepository.deleteUserFederatedAttributesByUserAndName(realm.getId(), userId, name);
    }

    private void persistAttributeValue(RealmModel realm, String userId, String name, String value) {
        FederatedUserAttribute attr = new FederatedUserAttribute();
        attr.setId(KeycloakModelUtils.generateId());
        attr.setName(name);
        attr.setValue(value);
        attr.setUserId(userId);
        attr.setRealmId(realm.getId());
        attr.setStorageProviderId(new StorageId(userId).getProviderId());
        federatedUserAttributeRepository.save(attr);
    }

    @Override
    public void setSingleAttribute(RealmModel realm, String userId, String name, String value) {
        createIndex(realm, userId);
        deleteAttribute(realm, userId, name);
        persistAttributeValue(realm, userId, name, value);
    }

    @Override
    public void removeAttribute(RealmModel realm, String userId, String name) {
        deleteAttribute(realm, userId, name);
    }

    @Override
    public MultivaluedHashMap<String, String> getAttributes(RealmModel realm, String userId) {
        List<FederatedUserAttribute> list = federatedUserAttributeRepository.getFederatedAttributesByUser(realm.getId(), userId);
        MultivaluedHashMap<String, String> result = new MultivaluedHashMap<>();
        for (FederatedUserAttribute entity : list) {
            result.add(entity.getName(), entity.getValue());
        }
        return result;
    }

    @Override
    public List<String> getUsersByUserAttribute(RealmModel realm, String name, String value) {
        return federatedUserAttributeRepository.getFederatedAttributesByNameAndValue(realm.getId(), name, value);
    }

    @Override
    public String getUserByFederatedIdentity(FederatedIdentityModel link, RealmModel realm) {
        List<String> results = brokerLinkRepository.findUserByBrokerLinkAndRealm(realm.getId(), link.getIdentityProvider(), link.getUserId());
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More results found for identityProvider=" + link.getIdentityProvider() +
                    ", userId=" + link.getUserId() + ", results=" + results);
        } else {
            return results.get(0);
        }
    }

    @Override
    public void addFederatedIdentity(RealmModel realm, String userId, FederatedIdentityModel link) {
        createIndex(realm, userId);
        BrokerLink entity = new BrokerLink();
        entity.setRealmId(realm.getId());
        entity.setUserId(userId);
        entity.setBrokerUserId(link.getUserId());
        entity.setIdentityProvider(link.getIdentityProvider());
        entity.setToken(link.getToken());
        entity.setBrokerUserName(link.getUserName());
        entity.setStorageProviderId(new StorageId(userId).getProviderId());
        brokerLinkRepository.save(entity);
    }

    @Override
    public boolean removeFederatedIdentity(RealmModel realm, String userId, String socialProvider) {
        BrokerLink entity = getBrokerLinkEntity(realm, userId, socialProvider);
        if (entity == null) return false;
        brokerLinkRepository.delete(entity);
        return true;
    }

    private BrokerLink getBrokerLinkEntity(RealmModel realm, String userId, String socialProvider) {
        List<BrokerLink> results = brokerLinkRepository.findBrokerLinkByUserAndProvider(realm.getId(), userId, socialProvider);
        return results.size() > 0 ? results.get(0) : null;
    }

    @Override
    public void updateFederatedIdentity(RealmModel realm, String userId, FederatedIdentityModel model) {
        createIndex(realm, userId);
        BrokerLink entity = getBrokerLinkEntity(realm, userId, model.getIdentityProvider());
        if (entity == null) return;
        entity.setBrokerUserName(model.getUserName());
        entity.setBrokerUserId(model.getUserId());
        entity.setToken(model.getToken());
        brokerLinkRepository.save(entity);
    }

    @Override
    public Set<FederatedIdentityModel> getFederatedIdentities(String userId, RealmModel realm) {
        List<BrokerLink> results = brokerLinkRepository.findBrokerLinkByUser(userId);
        Set<FederatedIdentityModel> set = new HashSet<>();
        for (BrokerLink entity : results) {
            FederatedIdentityModel model = new FederatedIdentityModel(entity.getIdentityProvider(), entity.getBrokerUserId(), entity.getBrokerUserName(), entity.getToken());
            set.add(model);
        }
        return set;
    }

    @Override
    public FederatedIdentityModel getFederatedIdentity(String userId, String socialProvider, RealmModel realm) {
        BrokerLink entity = getBrokerLinkEntity(realm, userId, socialProvider);
        if (entity == null) return null;
        return new FederatedIdentityModel(entity.getIdentityProvider(), entity.getBrokerUserId(), entity.getBrokerUserName(), entity.getToken());
    }

    @Override
    public void addConsent(RealmModel realm, String userId, UserConsentModel consent) {
        createIndex(realm, userId);
        String clientId = consent.getClient().getId();

        FederatedUserConsent consentEntity = getGrantedConsentEntity(userId, clientId);
        if (consentEntity != null) {
            throw new ModelDuplicateException("Consent already exists for client [" + clientId + "] and user [" + userId + "]");
        }

        consentEntity = new FederatedUserConsent();
        consentEntity.setId(KeycloakModelUtils.generateId());
        consentEntity.setUserId(userId);
        StorageId clientStorageId = new StorageId(clientId);
        if (clientStorageId.isLocal()) {
            consentEntity.setClientId(clientId);
        } else {
            consentEntity.setClientStorageProvider(clientStorageId.getProviderId());
            consentEntity.setExternalClientId(clientStorageId.getExternalId());
        }
        consentEntity.setRealmId(realm.getId());
        consentEntity.setStorageProviderId(new StorageId(userId).getProviderId());
        long currentTime = Time.currentTimeMillis();
        consentEntity.setCreatedDate(currentTime);
        consentEntity.setLastUpdatedDate(currentTime);
        federatedUserConsentRepository.save(consentEntity);

        updateGrantedConsentEntity(consentEntity, consent);
    }

    @Override
    public UserConsentModel getConsentByClient(RealmModel realm, String userId, String clientInternalId) {
        FederatedUserConsent entity = getGrantedConsentEntity(userId, clientInternalId);
        return toConsentModel(realm, entity);
    }

    @Override
    public List<UserConsentModel> getConsents(RealmModel realm, String userId) {
        List<FederatedUserConsent> results = federatedUserConsentRepository.userFederatedConsentsByUser(userId);
        List<UserConsentModel> consents = new ArrayList<>();
        for (FederatedUserConsent entity : results) {
            UserConsentModel model = toConsentModel(realm, entity);
            consents.add(model);
        }
        return consents;
    }

    @Override
    public void updateConsent(RealmModel realm, String userId, UserConsentModel consent) {
        createIndex(realm, userId);
        String clientId = consent.getClient().getId();

        FederatedUserConsent consentEntity = getGrantedConsentEntity(userId, clientId);
        if (consentEntity == null) {
            throw new ModelException("Consent not found for client [" + clientId + "] and user [" + userId + "]");
        }

        updateGrantedConsentEntity(consentEntity, consent);

    }

    @Override
    public boolean revokeConsentForClient(RealmModel realm, String userId, String clientInternalId) {
        FederatedUserConsent consentEntity = getGrantedConsentEntity(userId, clientInternalId);
        if (consentEntity == null) return false;
        federatedUserConsentRepository.delete(consentEntity);
        return true;
    }

    private FederatedUserConsent getGrantedConsentEntity(String userId, String clientId) {
        List<FederatedUserConsent> results;

        StorageId clientStorageId = new StorageId(clientId);
        if (clientStorageId.isLocal()) {
            results = federatedUserConsentRepository.userFederatedConsentByUserAndClient(userId, clientId);
        } else {
            results = federatedUserConsentRepository.userFederatedConsentByUserAndExternalClient(userId, clientStorageId.getProviderId(), clientStorageId.getExternalId());
        }
        if (results.size() > 1) {
            throw new ModelException("More results found for user [" + userId + "] and client [" + clientId + "]");
        } else if (results.size() == 1) {
            return results.get(0);
        } else {
            return null;
        }
    }

    private UserConsentModel toConsentModel(RealmModel realm, FederatedUserConsent entity) {
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
        UserConsentModel model = new UserConsentModel(client);
        model.setCreatedDate(entity.getCreatedDate());
        model.setLastUpdatedDate(entity.getLastUpdatedDate());

        Collection<FederatedUserConsentClientScope> grantedClientScopeEntities = entity.getGrantedClientScopes();
        if (grantedClientScopeEntities != null) {
            for (FederatedUserConsentClientScope grantedClientScope : grantedClientScopeEntities) {
                ClientScopeModel grantedClientScopeModel = realm.getClientScopeById(grantedClientScope.getScopeId());
                if (grantedClientScopeModel != null) {
                    model.addGrantedClientScope(grantedClientScopeModel);
                }
            }
        }

        return model;
    }

    // Update roles and protocolMappers to given consentEntity from the consentModel
    private void updateGrantedConsentEntity(FederatedUserConsent consentEntity, UserConsentModel consentModel) {
        Collection<FederatedUserConsentClientScope> grantedClientScopeEntities = consentEntity.getGrantedClientScopes();
        Collection<FederatedUserConsentClientScope> scopesToRemove = new HashSet<>(grantedClientScopeEntities);

        for (ClientScopeModel clientScope : consentModel.getGrantedClientScopes()) {
            FederatedUserConsentClientScope grantedClientScopeEntity = new FederatedUserConsentClientScope();
            grantedClientScopeEntity.setUserConsent(consentEntity);
            grantedClientScopeEntity.setScopeId(clientScope.getId());

            // Check if it's already there
            if (!grantedClientScopeEntities.contains(grantedClientScopeEntity)) {
                federatedUserConsentClientScopeRepository.save(grantedClientScopeEntity);
                grantedClientScopeEntities.add(grantedClientScopeEntity);
            } else {
                scopesToRemove.remove(grantedClientScopeEntity);
            }
        }
        // Those mappers were no longer on consentModel and will be removed
        for (FederatedUserConsentClientScope toRemove : scopesToRemove) {
            grantedClientScopeEntities.remove(toRemove);
            federatedUserConsentClientScopeRepository.delete(toRemove);
        }

        consentEntity.setLastUpdatedDate(Time.currentTimeMillis());
        federatedUserConsentRepository.save(consentEntity);
    }

    @Override
    public void setNotBeforeForUser(RealmModel realm, String userId, int notBefore) {
        // Track it as attribute for now
        String notBeforeStr = String.valueOf(notBefore);
        setSingleAttribute(realm, userId, "fedNotBefore", notBeforeStr);
    }

    @Override
    public int getNotBeforeOfUser(RealmModel realm, String userId) {
        MultivaluedHashMap<String, String> attrs = getAttributes(realm, userId);
        String notBeforeStr = attrs.getFirst("fedNotBefore");

        return notBeforeStr == null ? 0 : Integer.parseInt(notBeforeStr);
    }

    @Override
    public Set<GroupModel> getGroups(RealmModel realm, String userId) {
        Set<GroupModel> set = new HashSet<>();
        List<FederatedUserGroupMembership> results = federatedUserGroupMembershipRepository.feduserGroupMembership(userId);
        if (results.size() == 0) return set;
        for (FederatedUserGroupMembership entity : results) {
            GroupModel group = realm.getGroupById(entity.getGroupId());
            set.add(group);
        }
        return set;
    }

    @Override
    public void joinGroup(RealmModel realm, String userId, GroupModel group) {
        createIndex(realm, userId);
        FederatedUserGroupMembership entity = new FederatedUserGroupMembership();
        entity.setUserId(userId);
        entity.setStorageProviderId(new StorageId(userId).getProviderId());
        entity.setGroupId(group.getId());
        entity.setRealmId(realm.getId());
        federatedUserGroupMembershipRepository.save(entity);
    }

    @Override
    public void leaveGroup(RealmModel realm, String userId, GroupModel group) {
        if (userId == null || group == null) return;
        List<FederatedUserGroupMembership> results = federatedUserGroupMembershipRepository.feduserMemberOf(userId, group.getId());
        if (results.size() == 0) return;
        for (FederatedUserGroupMembership entity : results) {
            federatedUserGroupMembershipRepository.delete(entity);
        }
    }

    @Override
    public List<String> getMembership(RealmModel realm, GroupModel group, int firstResult, int max) {
        return federatedUserGroupMembershipRepository.fedgroupMembership(realm.getId(), group.getId());
    }

    @Override
    public Set<String> getRequiredActions(RealmModel realm, String userId) {
        Set<String> set = new HashSet<>();
        List<FederatedUserRequiredAction> values = getRequiredActionEntities(realm, userId);
        for (FederatedUserRequiredAction entity : values) {
            set.add(entity.getAction());
        }

        return set;
    }

    private List<FederatedUserRequiredAction> getRequiredActionEntities(RealmModel realm, String userId) {
        return federatedUserRequiredActionRepository.getFederatedUserRequiredActionsByUser(userId, realm.getId());
    }

    @Override
    public void addRequiredAction(RealmModel realm, String userId, String action) {
        Key key = new FederatedUserRequiredAction.Key(userId, action);
        Optional<FederatedUserRequiredAction> optional = federatedUserRequiredActionRepository.findById(key);
        if (!optional.isPresent()) {
            createIndex(realm, userId);
            FederatedUserRequiredAction entity = new FederatedUserRequiredAction();
            entity.setUserId(userId);
            entity.setRealmId(realm.getId());
            entity.setStorageProviderId(new StorageId(userId).getProviderId());
            entity.setAction(action);
            federatedUserRequiredActionRepository.save(entity);
        }
    }

    @Override
    public void removeRequiredAction(RealmModel realm, String userId, String action) {
        List<FederatedUserRequiredAction> values = getRequiredActionEntities(realm, userId);
        for (FederatedUserRequiredAction entity : values) {
            if (action.equals(entity.getAction())) {
                federatedUserRequiredActionRepository.delete(entity);
            }
        }
    }

    @Override
    public void grantRole(RealmModel realm, String userId, RoleModel role) {
        createIndex(realm, userId);
        FederatedUserRoleMapping entity = new FederatedUserRoleMapping();
        entity.setUserId(userId);
        entity.setStorageProviderId(new StorageId(userId).getProviderId());
        entity.setRealmId(realm.getId());
        entity.setRoleId(role.getId());
        federatedUserRoleMappingRepository.save(entity);
    }

    @Override
    public Set<RoleModel> getRoleMappings(RealmModel realm, String userId) {
        Set<RoleModel> set = new HashSet<>();
        List<FederatedUserRoleMapping> results = federatedUserRoleMappingRepository.feduserRoleMappings(userId);
        if (results.size() == 0) return set;
        for (FederatedUserRoleMapping entity : results) {
            RoleModel role = realm.getRoleById(entity.getRoleId());
            set.add(role);
        }
        return set;
    }

    @Override
    public void deleteRoleMapping(RealmModel realm, String userId, RoleModel role) {
        List<FederatedUserRoleMapping> results = federatedUserRoleMappingRepository.feduserRoleMappings(userId);
        for (FederatedUserRoleMapping entity : results) {
            if (entity.getRoleId().equals(role.getId())) {
                federatedUserRoleMappingRepository.delete(entity);
            }
        }
    }

    @Override
    public void updateCredential(RealmModel realm, String userId, CredentialModel cred) {
        Optional<FederatedUserCredential> optional = federatedUserCredentialRepository.findById(cred.getId());
        if (!optional.isPresent()) return;
        createIndex(realm, userId);
        FederatedUserCredential entity = optional.get();
        entity.setCreatedDate(cred.getCreatedDate());
        entity.setType(cred.getType());
        entity.setCredentialData(cred.getCredentialData());
        entity.setSecretData(cred.getSecretData());
        cred.setUserLabel(entity.getUserLabel());
        federatedUserCredentialRepository.save(entity);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, String userId, CredentialModel cred) {
        createIndex(realm, userId);
        FederatedUserCredential entity = new FederatedUserCredential();
        String id = cred.getId() == null ? KeycloakModelUtils.generateId() : cred.getId();
        entity.setId(id);
        entity.setCreatedDate(cred.getCreatedDate());
        entity.setType(cred.getType());
        entity.setCredentialData(cred.getCredentialData());
        entity.setSecretData(cred.getSecretData());
        entity.setUserLabel(cred.getUserLabel());

        entity.setUserId(userId);
        entity.setRealmId(realm.getId());
        entity.setStorageProviderId(new StorageId(userId).getProviderId());

        //add in linkedlist to last position
        List<FederatedUserCredential> credentials = getStoredCredentialEntities(userId);
        int priority = credentials.isEmpty() ? JpaUserCredentialStore.PRIORITY_DIFFERENCE : credentials.get(credentials.size() - 1).getPriority() + JpaUserCredentialStore.PRIORITY_DIFFERENCE;
        entity.setPriority(priority);
        federatedUserCredentialRepository.save(entity);
        return toModel(entity);
    }

    @Override
    public boolean removeStoredCredential(RealmModel realm, String userId, String id) {
        Optional<FederatedUserCredential> optional = federatedUserCredentialRepository.findById(id);
        if (!optional.isPresent()) return false;

        FederatedUserCredential entity = optional.get();

        int currentPriority = entity.getPriority();
        List<FederatedUserCredential> credentials = getStoredCredentialEntities(userId);

        // Decrease priority of all credentials after our
        for (FederatedUserCredential cred : credentials) {
            if (cred.getPriority() > currentPriority) {
                cred.setPriority(cred.getPriority() - JpaUserCredentialStore.PRIORITY_DIFFERENCE);
            }
        }

        federatedUserCredentialRepository.delete(entity);
        return true;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realm, String userId, String id) {
        Optional<FederatedUserCredential> optional = federatedUserCredentialRepository.findById(id);
        return optional.map(this::toModel).orElse(null);
    }

    protected CredentialModel toModel(FederatedUserCredential entity) {
        CredentialModel model = new CredentialModel();
        model.setId(entity.getId());
        model.setType(entity.getType());
        model.setCreatedDate(entity.getCreatedDate());
        model.setUserLabel(entity.getUserLabel());

        // Backwards compatibility - users from previous version still have "salt" in the DB filled.
        // We migrate it to new secretData format on-the-fly
        if (entity.getSalt() != null) {
            String newSecretData = entity.getSecretData().replace("__SALT__", Base64.encodeBytes(entity.getSalt()));
            entity.setSecretData(newSecretData);
            entity.setSalt(null);
        }

        model.setSecretData(entity.getSecretData());
        model.setCredentialData(entity.getCredentialData());
        return model;
    }

    @Override
    public List<CredentialModel> getStoredCredentials(RealmModel realm, String userId) {
        List<FederatedUserCredential> results = getStoredCredentialEntities(userId);
        List<CredentialModel> rtn = new LinkedList<>();
        for (FederatedUserCredential entity : results) {
            rtn.add(toModel(entity));
        }
        return rtn;
    }

    private List<FederatedUserCredential> getStoredCredentialEntities(String userId) {
        return federatedUserCredentialRepository.federatedUserCredentialByUser(userId);
    }

    @Override
    public List<CredentialModel> getStoredCredentialsByType(RealmModel realm, String userId, String type) {
        List<FederatedUserCredential> results = federatedUserCredentialRepository.federatedUserCredentialByUserAndType(type, userId);
        List<CredentialModel> rtn = new LinkedList<>();
        for (FederatedUserCredential entity : results) {
            rtn.add(toModel(entity));
        }
        return rtn;
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realm, String userId, String name, String type) {
        List<FederatedUserCredential> results = federatedUserCredentialRepository.federatedUserCredentialByNameAndType(type, name, userId);
        if (results.isEmpty()) return null;
        return toModel(results.get(0));
    }

    @Override
    public List<String> getStoredUsers(RealmModel realm, int first, int max) {
        return federatedUserRepository.getFederatedUserIds(realm.getId());
    }

    @Override
    public void updateCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        updateCredential(realm, user.getId(), cred);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        return createCredential(realm, user.getId(), cred);
    }

    @Override
    public boolean removeStoredCredential(RealmModel realm, UserModel user, String id) {
        return removeStoredCredential(realm, user.getId(), id);
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realm, UserModel user, String id) {
        return getStoredCredentialById(realm, user.getId(), id);
    }

    @Override
    public List<CredentialModel> getStoredCredentials(RealmModel realm, UserModel user) {
        return getStoredCredentials(realm, user.getId());
    }

    @Override
    public List<CredentialModel> getStoredCredentialsByType(RealmModel realm, UserModel user, String type) {
        return getStoredCredentialsByType(realm, user.getId(), type);
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realm, UserModel user, String name, String type) {
        return getStoredCredentialByNameAndType(realm, user.getId(), name, type);
    }

    @Override
    public boolean moveCredentialTo(RealmModel realm, UserModel user, String id, String newPreviousCredentialId) {
        List<FederatedUserCredential> sortedCreds = getStoredCredentialEntities(user.getId());
        // 1 - Create new list and move everything to it.
        List<FederatedUserCredential> newList = new ArrayList<>(sortedCreds);

        // 2 - Find indexes of our and newPrevious credential
        int ourCredentialIndex = -1;
        int newPreviousCredentialIndex = -1;
        FederatedUserCredential ourCredential = null;
        int i = 0;
        for (FederatedUserCredential credential : newList) {
            if (id.equals(credential.getId())) {
                ourCredentialIndex = i;
                ourCredential = credential;
            } else if (newPreviousCredentialId != null && newPreviousCredentialId.equals(credential.getId())) {
                newPreviousCredentialIndex = i;
            }
            i++;
        }

        if (ourCredentialIndex == -1) {
            LOG.warn("Not found credential with id [{}] of user [{}]", id, user.getUsername());
            return false;
        }

        if (newPreviousCredentialId != null && newPreviousCredentialIndex == -1) {
            LOG.warn("Can't move up credential with id [{}] of user [{}]", id, user.getUsername());
            return false;
        }

        // 3 - Compute index where we move our credential
        int toMoveIndex = newPreviousCredentialId == null ? 0 : newPreviousCredentialIndex + 1;

        // 4 - Insert our credential to new position, remove it from the old position
        newList.add(toMoveIndex, ourCredential);
        int indexToRemove = toMoveIndex < ourCredentialIndex ? ourCredentialIndex + 1 : ourCredentialIndex;
        newList.remove(indexToRemove);

        // 5 - newList contains credentials in requested order now. Iterate through whole list and change priorities accordingly.
        int expectedPriority = 0;
        for (FederatedUserCredential credential : newList) {
            expectedPriority += JpaUserCredentialStore.PRIORITY_DIFFERENCE;
            if (credential.getPriority() != expectedPriority) {
                credential.setPriority(expectedPriority);

                LOG.trace("Priority of credential [{}] of user [{}] changed to [{}]", credential.getId(), user.getUsername(), expectedPriority);
            }
        }
        return true;
    }

    @Override
    public int getStoredUsersCount(RealmModel realm) {
        return federatedUserRepository.getFederatedUserCount(realm.getId());
    }

    @Override
    public void preRemove(RealmModel realm) {
        federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByRealm(realm.getId());
        federatedUserConsentRepository.deleteFederatedUserConsentsByRealm(realm.getId());
        federatedUserRoleMappingRepository.deleteFederatedUserRoleMappingsByRealm(realm.getId());
        federatedUserRequiredActionRepository.deleteFederatedUserRequiredActionsByRealm(realm.getId());
        brokerLinkRepository.deleteBrokerLinkByRealm(realm.getId());
        federatedUserCredentialRepository.deleteFederatedUserCredentialsByRealm(realm.getId());
        federatedUserAttributeRepository.deleteUserFederatedAttributesByRealm(realm.getId());
        federatedUserGroupMembershipRepository.deleteFederatedUserGroupMembershipByRealm(realm.getId());
        federatedUserRepository.deleteFederatedUsersByRealm(realm.getId());
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        federatedUserRoleMappingRepository.deleteFederatedUserRoleMappingsByRole(role.getId());
    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        federatedUserGroupMembershipRepository.deleteFederatedUserGroupMembershipsByGroup(group.getId());
    }

    @Override
    public void preRemove(RealmModel realm, ClientModel client) {
        StorageId clientStorageId = new StorageId(client.getId());
        if (clientStorageId.isLocal()) {
            federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByClient(client.getId());
            federatedUserConsentRepository.deleteFederatedUserConsentsByClient(client.getId());
        } else {
            federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByExternalClient(
                    clientStorageId.getProviderId(), clientStorageId.getExternalId()
            );
            federatedUserConsentRepository.deleteFederatedUserConsentsByExternalClient(
                    clientStorageId.getProviderId(), clientStorageId.getExternalId()
            );
        }
    }

    @Override
    public void preRemove(ProtocolMapperModel protocolMapper) {
        // No op
    }

    @Override
    public void preRemove(ClientScopeModel clientScope) {
        federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByClientScope(clientScope.getId());
    }

    @Override
    public void preRemove(RealmModel realm, UserModel user) {
        brokerLinkRepository.deleteBrokerLinkByUser(user.getId(), realm.getId());
        federatedUserAttributeRepository.deleteUserFederatedAttributesByUser(user.getId(), realm.getId());
        federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByUser(user.getId(), realm.getId());
        federatedUserConsentRepository.deleteFederatedUserConsentsByUser(user.getId(), realm.getId());
        federatedUserCredentialRepository.deleteFederatedUserCredentialByUser(user.getId(), realm.getId());
        federatedUserGroupMembershipRepository.deleteFederatedUserGroupMembershipsByUser(user.getId(), realm.getId());
        federatedUserRequiredActionRepository.deleteFederatedUserRequiredActionsByUser(user.getId(), realm.getId());
        federatedUserRoleMappingRepository.deleteFederatedUserRoleMappingsByUser(user.getId(), realm.getId());
        federatedUserRepository.deleteFederatedUserByUser(user.getId(), realm.getId());
    }

    @Override
    public void preRemove(RealmModel realm, ComponentModel model) {
        if (model.getProviderType().equals(UserStorageProvider.class.getName())) {
            brokerLinkRepository.deleteBrokerLinkByStorageProvider(model.getId());
            federatedUserAttributeRepository.deleteFederatedAttributesByStorageProvider(model.getId());
            federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByStorageProvider(model.getId());
            federatedUserConsentRepository.deleteFederatedUserConsentsByStorageProvider(model.getId());
            federatedUserCredentialRepository.deleteFederatedUserCredentialsByStorageProvider(model.getId());
            federatedUserGroupMembershipRepository.deleteFederatedUserGroupMembershipByStorageProvider(model.getId());
            federatedUserRequiredActionRepository.deleteFederatedUserRequiredActionsByStorageProvider(model.getId());
            federatedUserRoleMappingRepository.deleteFederatedUserRoleMappingsByStorageProvider(model.getId());
            federatedUserRepository.deleteFederatedUsersByStorageProvider(model.getId());
        } else if (model.getProviderType().equals(ClientStorageProvider.class.getName())) {
            federatedUserConsentClientScopeRepository.deleteFederatedUserConsentClientScopesByClientStorageProvider(model.getId());
            federatedUserConsentRepository.deleteFederatedUserConsentsByClientStorageProvider(model.getId());
        }
    }
}
