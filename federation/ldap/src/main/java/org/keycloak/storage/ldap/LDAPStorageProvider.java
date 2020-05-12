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

package org.keycloak.storage.ldap;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialAuthentication;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.DefaultRoles;
import org.keycloak.models.utils.ReadOnlyUserModelDelegate;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.adapter.InMemoryUserAdapter;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPOperationDecorator;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapperManager;
import org.keycloak.storage.ldap.mappers.PasswordUpdateCallback;
import org.keycloak.storage.user.ImportedUserValidation;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.naming.AuthenticationException;
import java.util.*;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class LDAPStorageProvider implements UserStorageProvider,
        CredentialInputValidator,
        CredentialInputUpdater,
        CredentialAuthentication,
        UserLookupProvider,
        UserRegistrationProvider,
        UserQueryProvider,
        ImportedUserValidation {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPStorageProvider.class);

    protected final Set<String> supportedCredentialTypes = new HashSet<>();
    protected LDAPStorageProviderFactory factory;
    protected KeycloakSession session;
    protected UserStorageProviderModel model;
    protected LDAPIdentityStore ldapIdentityStore;
    protected EditMode editMode;
    protected PasswordUpdateCallback updater;
    protected LDAPStorageMapperManager mapperManager;

    @Autowired
    private PasswordPolicyManagerProvider passwordPolicyManagerProvider;

    // these exist to make sure that we only hit ldap once per transaction
    //protected Map<String, UserModel> noImportSessionCache = new HashMap<>();
    protected LDAPStorageUserManager userManager;

    public LDAPStorageProvider(LDAPStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        this.factory = factory;
        this.session = session;
        this.model = new UserStorageProviderModel(model);
        this.ldapIdentityStore = ldapIdentityStore;
        this.editMode = ldapIdentityStore.getConfig().getEditMode();
        this.mapperManager = new LDAPStorageMapperManager(this);
        this.userManager = new LDAPStorageUserManager(this);

        supportedCredentialTypes.add(PasswordCredentialModel.TYPE);
    }

    public void setUpdater(PasswordUpdateCallback updater) {
        this.updater = updater;
    }

    public KeycloakSession getSession() {
        return session;
    }

    public LDAPIdentityStore getLdapIdentityStore() {
        return this.ldapIdentityStore;
    }

    public EditMode getEditMode() {
        return editMode;
    }

    public UserStorageProviderModel getModel() {
        return model;
    }

    public LDAPStorageMapperManager getMapperManager() {
        return mapperManager;
    }

    public LDAPStorageUserManager getUserManager() {
        return userManager;
    }


    @Override
    public UserModel validate(RealmModel realm, UserModel local) {
        LDAPObject ldapObject = loadAndValidateUser(realm, local);
        if (ldapObject == null) {
            return null;
        }

        return proxy(realm, local, ldapObject);
    }

    protected UserModel proxy(RealmModel realm, UserModel local, LDAPObject ldapObject) {
        UserModel existing = userManager.getManagedProxiedUser(local.getId());
        if (existing != null) {
            return existing;
        }

        // We need to avoid having CachedUserModel as cache is upper-layer then LDAP. Hence having CachedUserModel here may cause StackOverflowError
        if (local instanceof CachedUserModel) {
            local = session.userStorageManager().getUserById(local.getId(), realm);

            existing = userManager.getManagedProxiedUser(local.getId());
            if (existing != null) {
                return existing;
            }
        }

        UserModel proxied = local;

        checkDNChanged(realm, local, ldapObject);

        switch (editMode) {
            case READ_ONLY:
                if (model.isImportEnabled()) {
                    proxied = new ReadonlyLDAPUserModelDelegate(local, this);
                } else {
                    proxied = new ReadOnlyUserModelDelegate(local);
                }
                break;
            case WRITABLE:
                proxied = new WritableLDAPUserModelDelegate(local, this, ldapObject);
                break;
            case UNSYNCED:
                proxied = new UnsyncedLDAPUserModelDelegate(local, this);
        }

        List<ComponentModel> mappers = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
        List<ComponentModel> sortedMappers = mapperManager.sortMappersAsc(mappers);
        for (ComponentModel mapperModel : sortedMappers) {
            LDAPStorageMapper ldapMapper = mapperManager.getMapper(mapperModel);
            proxied = ldapMapper.proxy(ldapObject, proxied, realm);
        }

        userManager.setManagedProxiedUser(proxied, ldapObject);

        return proxied;
    }

    private void checkDNChanged(RealmModel realm, UserModel local, LDAPObject ldapObject) {
        String dnFromDB = local.getFirstAttribute(LDAPConstants.LDAP_ENTRY_DN);
        String ldapDn = ldapObject.getDn().toString();
        if (!ldapDn.equals(dnFromDB)) {
            LOG.debug("Updated LDAP DN of user '{}' to '{}'", local.getUsername(), ldapDn);
            local.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, ldapDn);

            UserCache userCache = session.userCache();
            if (userCache != null) {
                userCache.evict(realm, local);
            }
        }
    }

    @Override
    public boolean supportsCredentialAuthenticationFor(String type) {
        return type.equals(UserCredentialModel.KERBEROS);
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            Condition attrCondition = conditionsBuilder.equal(attrName, attrValue, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(attrCondition);

            List<LDAPObject> ldapObjects = ldapQuery.getResultList();

            if (ldapObjects == null || ldapObjects.isEmpty()) {
                return Collections.emptyList();
            }

            List<UserModel> searchResults = new LinkedList<UserModel>();

            for (LDAPObject ldapUser : ldapObjects) {
                String ldapUsername = LDAPUtils.getUsername(ldapUser, this.ldapIdentityStore.getConfig());
                if (session.userLocalStorage().getUserByUsername(ldapUsername, realm) == null) {
                    UserModel imported = importUserFromLDAP(session, realm, ldapUser);
                    searchResults.add(imported);
                }
            }

            return searchResults;
        }
    }

    public boolean synchronizeRegistrations() {
        return "true".equalsIgnoreCase(model.getConfig().getFirst(LDAPConstants.SYNC_REGISTRATIONS)) && editMode == UserStorageProvider.EditMode.WRITABLE;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        if (!synchronizeRegistrations()) {
            return null;
        }
        UserModel user;
        if (model.isImportEnabled()) {
            user = session.userLocalStorage().addUser(realm, username);
            user.setFederationLink(model.getId());
        } else {
            user = new InMemoryUserAdapter(session, realm, new StorageId(model.getId(), username).getId());
            user.setUsername(username);
        }
        LDAPObject ldapUser = LDAPUtils.addUserToLDAP(this, realm, user);
        LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());
        user.setSingleAttribute(LDAPConstants.LDAP_ID, ldapUser.getUuid());
        user.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, ldapUser.getDn().toString());

        // Add the user to the default groups and add default required actions
        UserModel proxy = proxy(realm, user, ldapUser);
        DefaultRoles.addDefaultRoles(realm, proxy);

        for (GroupModel g : realm.getDefaultGroups()) {
            proxy.joinGroup(g);
        }
        for (RequiredActionProviderModel r : realm.getRequiredActionProviders()) {
            if (r.isEnabled() && r.isDefaultAction()) {
                proxy.addRequiredAction(r.getAlias());
            }
        }

        return proxy;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        if (editMode == UserStorageProvider.EditMode.READ_ONLY || editMode == UserStorageProvider.EditMode.UNSYNCED) {
            LOG.warn("User '{}' can't be deleted in LDAP as editMode is '{}'. Deleting user just from Keycloak DB, but he will be re-imported from LDAP again once searched in Keycloak", user.getUsername(), editMode.toString());
            return true;
        }

        LDAPObject ldapObject = loadAndValidateUser(realm, user);
        if (ldapObject == null) {
            LOG.warn("User '{}' can't be deleted from LDAP as it doesn't exist here", user.getUsername());
            return false;
        }

        ldapIdentityStore.remove(ldapObject);
        userManager.removeManagedUserEntry(user.getId());

        return true;
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        UserModel alreadyLoadedInSession = userManager.getManagedProxiedUser(id);
        if (alreadyLoadedInSession != null) return alreadyLoadedInSession;

        StorageId storageId = new StorageId(id);
        return getUserByUsername(storageId.getExternalId(), realm);
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return 0;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return Collections.EMPTY_LIST;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        return Collections.EMPTY_LIST;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search, realm, 0, Integer.MAX_VALUE - 1);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        Map<String, String> attributes = new HashMap<String, String>();
        attributes.put(UserModel.SEARCH, search);
        return searchForUser(attributes, realm, firstResult, maxResults);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return searchForUser(params, realm, 0, Integer.MAX_VALUE - 1);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        String search = params.get(UserModel.SEARCH);
        if (search != null) {
            int spaceIndex = search.lastIndexOf(' ');
            if (spaceIndex > -1) {
                String firstName = search.substring(0, spaceIndex).trim();
                String lastName = search.substring(spaceIndex).trim();
                params.put(UserModel.FIRST_NAME, firstName);
                params.put(UserModel.LAST_NAME, lastName);
            } else if (search.indexOf('@') > -1) {
                params.put(UserModel.USERNAME, search.trim().toLowerCase());
                params.put(UserModel.EMAIL, search.trim().toLowerCase());
            } else {
                params.put(UserModel.LAST_NAME, search.trim());
                params.put(UserModel.USERNAME, search.trim().toLowerCase());
            }
        }

        List<UserModel> searchResults = new LinkedList<UserModel>();

        List<LDAPObject> ldapUsers = searchLDAP(realm, params, maxResults + firstResult);
        int counter = 0;
        for (LDAPObject ldapUser : ldapUsers) {
            if (counter++ < firstResult) continue;
            String ldapUsername = LDAPUtils.getUsername(ldapUser, this.ldapIdentityStore.getConfig());
            if (session.userLocalStorage().getUserByUsername(ldapUsername, realm) == null) {
                UserModel imported = importUserFromLDAP(session, realm, ldapUser);
                searchResults.add(imported);
            }
        }

        return searchResults;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return getGroupMembers(realm, group, 0, Integer.MAX_VALUE - 1);
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        List<ComponentModel> mappers = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
        List<ComponentModel> sortedMappers = mapperManager.sortMappersAsc(mappers);
        for (ComponentModel mapperModel : sortedMappers) {
            LDAPStorageMapper ldapMapper = mapperManager.getMapper(mapperModel);
            List<UserModel> users = ldapMapper.getGroupMembers(realm, group, firstResult, maxResults);

            // Sufficient for now
            if (users.size() > 0) {
                return users;
            }
        }
        return Collections.emptyList();
    }

    public List<UserModel> loadUsersByUsernames(List<String> usernames, RealmModel realm) {
        List<UserModel> result = new ArrayList<>();
        for (String username : usernames) {
            UserModel kcUser = session.users().getUserByUsername(username, realm);
            if (kcUser == null) {
                LOG.warn("User '{}' referenced by membership wasn't found in LDAP", username);
            } else if (model.isImportEnabled() && !model.getId().equals(kcUser.getFederationLink())) {
                LOG.warn("Incorrect federation provider of user '{}'", kcUser.getUsername());
            } else {
                result.add(kcUser);
            }
        }
        return result;
    }

    protected List<LDAPObject> searchLDAP(RealmModel realm, Map<String, String> attributes, int maxResults) {

        List<LDAPObject> results = new ArrayList<LDAPObject>();
        if (attributes.containsKey(UserModel.USERNAME)) {
            try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
                LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

                // Mapper should replace "username" in parameter name with correct LDAP mapped attribute
                Condition usernameCondition = conditionsBuilder.equal(UserModel.USERNAME, attributes.get(UserModel.USERNAME), EscapeStrategy.NON_ASCII_CHARS_ONLY);
                ldapQuery.addWhereCondition(usernameCondition);

                List<LDAPObject> ldapObjects = ldapQuery.getResultList();
                results.addAll(ldapObjects);
            }
        }

        if (attributes.containsKey(UserModel.EMAIL)) {
            try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
                LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

                // Mapper should replace "email" in parameter name with correct LDAP mapped attribute
                Condition emailCondition = conditionsBuilder.equal(UserModel.EMAIL, attributes.get(UserModel.EMAIL), EscapeStrategy.NON_ASCII_CHARS_ONLY);
                ldapQuery.addWhereCondition(emailCondition);

                List<LDAPObject> ldapObjects = ldapQuery.getResultList();
                results.addAll(ldapObjects);
            }
        }

        if (attributes.containsKey(UserModel.FIRST_NAME) || attributes.containsKey(UserModel.LAST_NAME)) {
            try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
                LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

                // Mapper should replace parameter with correct LDAP mapped attributes
                if (attributes.containsKey(UserModel.FIRST_NAME)) {
                    ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.FIRST_NAME, attributes.get(UserModel.FIRST_NAME), EscapeStrategy.NON_ASCII_CHARS_ONLY));
                }
                if (attributes.containsKey(UserModel.LAST_NAME)) {
                    ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.LAST_NAME, attributes.get(UserModel.LAST_NAME), EscapeStrategy.NON_ASCII_CHARS_ONLY));
                }

                List<LDAPObject> ldapObjects = ldapQuery.getResultList();
                results.addAll(ldapObjects);
            }
        }

        return results;
    }

    /**
     * @param local
     * @return ldapUser corresponding to local user or null if user is no longer in LDAP
     */
    protected LDAPObject loadAndValidateUser(RealmModel realm, UserModel local) {
        LDAPObject existing = userManager.getManagedLDAPUser(local.getId());
        if (existing != null) {
            return existing;
        }

        LDAPObject ldapUser = loadLDAPUserByUsername(realm, local.getUsername());
        if (ldapUser == null) {
            return null;
        }
        LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());

        if (ldapUser.getUuid().equals(local.getFirstAttribute(LDAPConstants.LDAP_ID))) {
            return ldapUser;
        } else {
            LOG.warn("LDAP User invalid. ID doesn't match. ID from LDAP [{}], LDAP ID from local DB: [{}]", ldapUser.getUuid(), local.getFirstAttribute(LDAPConstants.LDAP_ID));
            return null;
        }
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        LDAPObject ldapUser = loadLDAPUserByUsername(realm, username);
        if (ldapUser == null) {
            return null;
        }

        return importUserFromLDAP(session, realm, ldapUser);
    }

    protected UserModel importUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser) {
        String ldapUsername = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
        LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());

        UserModel imported = null;
        if (model.isImportEnabled()) {
            imported = session.userLocalStorage().addUser(realm, ldapUsername);
        } else {
            InMemoryUserAdapter adapter = new InMemoryUserAdapter(session, realm, new StorageId(model.getId(), ldapUsername).getId());
            adapter.addDefaults();
            imported = adapter;
        }
        imported.setEnabled(true);

        List<ComponentModel> mappers = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
        List<ComponentModel> sortedMappers = mapperManager.sortMappersDesc(mappers);
        for (ComponentModel mapperModel : sortedMappers) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using mapper {} during import user from LDAP", mapperModel);
            }
            LDAPStorageMapper ldapMapper = mapperManager.getMapper(mapperModel);
            ldapMapper.onImportUserFromLDAP(ldapUser, imported, realm, true);
        }

        String userDN = ldapUser.getDn().toString();
        if (model.isImportEnabled()) imported.setFederationLink(model.getId());
        imported.setSingleAttribute(LDAPConstants.LDAP_ID, ldapUser.getUuid());
        imported.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, userDN);
        if (getLdapIdentityStore().getConfig().isTrustEmail()) {
            imported.setEmailVerified(true);
        }
        LOG.debug("Imported new user from LDAP to Keycloak DB. Username: [{}], Email: [{}], LDAP_ID: [{}], LDAP Entry DN: [{}]", imported.getUsername(), imported.getEmail(),
                ldapUser.getUuid(), userDN);
        return proxy(realm, imported, ldapUser);
    }

    protected LDAPObject queryByEmail(RealmModel realm, String email) {
        try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            // Mapper should replace "email" in parameter name with correct LDAP mapped attribute
            Condition emailCondition = conditionsBuilder.equal(UserModel.EMAIL, email, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(emailCondition);

            return ldapQuery.getFirstResult();
        }
    }


    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        LDAPObject ldapUser = queryByEmail(realm, email);
        if (ldapUser == null) {
            return null;
        }

        // Check here if user already exists
        String ldapUsername = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
        UserModel user = session.userLocalStorage().getUserByUsername(ldapUsername, realm);

        if (user != null) {
            LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());
            // If email attribute mapper is set to "Always Read Value From LDAP" the user may be in Keycloak DB with an old email address
            if (ldapUser.getUuid().equals(user.getFirstAttribute(LDAPConstants.LDAP_ID))) return user;
            throw new ModelDuplicateException("User with username '" + ldapUsername + "' already exists in Keycloak. It conflicts with LDAP user with email '" + email + "'");
        }

        return importUserFromLDAP(session, realm, ldapUser);
    }

    @Override
    public void preRemove(RealmModel realm) {
        // complete Don't think we have to do anything
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        // TODO: Maybe mappers callback to ensure role deletion propagated to LDAP by RoleLDAPFederationMapper?
    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {

    }

    public boolean validPassword(RealmModel realm, UserModel user, String password) {
        // Use Naming LDAP API
        LDAPObject ldapUser = loadAndValidateUser(realm, user);

        try {
            ldapIdentityStore.validatePassword(ldapUser, password);
            return true;
        } catch (AuthenticationException ae) {
            boolean processed = false;
            List<ComponentModel> mappers = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
            List<ComponentModel> sortedMappers = mapperManager.sortMappersDesc(mappers);
            for (ComponentModel mapperModel : sortedMappers) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Using mapper {} during import user from LDAP", mapperModel);
                }
                LDAPStorageMapper ldapMapper = mapperManager.getMapper(mapperModel);
                processed = processed || ldapMapper.onAuthenticationFailure(ldapUser, user, ae, realm);
            }
            return processed;
        }
    }


    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!PasswordCredentialModel.TYPE.equals(input.getType()) || !(input instanceof UserCredentialModel))
            return false;
        if (editMode == UserStorageProvider.EditMode.READ_ONLY) {
            throw new ReadOnlyException("Federated storage is not writable");

        } else if (editMode == UserStorageProvider.EditMode.WRITABLE) {
            LDAPIdentityStore ldapIdentityStore = getLdapIdentityStore();
            String password = input.getChallengeResponse();
            LDAPObject ldapUser = loadAndValidateUser(realm, user);
            if (ldapIdentityStore.getConfig().isValidatePasswordPolicy()) {
                PolicyError error = passwordPolicyManagerProvider.validate(realm, user, password);
                if (error != null) throw new ModelException(error.getMessage(), error.getParameters());
            }
            try {
                LDAPOperationDecorator operationDecorator = null;
                if (updater != null) {
                    operationDecorator = updater.beforePasswordUpdate(user, ldapUser, (UserCredentialModel) input);
                }

                ldapIdentityStore.updatePassword(ldapUser, password, operationDecorator);

                if (updater != null) updater.passwordUpdated(user, ldapUser, (UserCredentialModel) input);
                return true;
            } catch (ModelException me) {
                if (updater != null) {
                    updater.passwordUpdateFailed(user, ldapUser, (UserCredentialModel) input, me);
                    return false;
                } else {
                    throw me;
                }
            }

        } else {
            return false;
        }
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }

    public Set<String> getSupportedCredentialTypes() {
        return new HashSet<String>(this.supportedCredentialTypes);
    }


    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getSupportedCredentialTypes().contains(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return getSupportedCredentialTypes().contains(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) return false;
        if (input.getType().equals(PasswordCredentialModel.TYPE) && !session.userCredentialManager().isConfiguredLocally(realm, user, PasswordCredentialModel.TYPE)) {
            return validPassword(realm, user, input.getChallengeResponse());
        } else {
            return false; // invalid cred type
        }
    }

    @Override
    public CredentialValidationOutput authenticate(RealmModel realm, CredentialInput cred) {
        if (!(cred instanceof UserCredentialModel)) CredentialValidationOutput.failed();

        return CredentialValidationOutput.failed();
    }

    @Override
    public void close() {
    }

    public LDAPObject loadLDAPUserByUsername(RealmModel realm, String username) {
        try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            String usernameMappedAttribute = this.ldapIdentityStore.getConfig().getUsernameLdapAttribute();
            Condition usernameCondition = conditionsBuilder.equal(usernameMappedAttribute, username, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(usernameCondition);

            LDAPObject ldapUser = ldapQuery.getFirstResult();
            if (ldapUser == null) {
                return null;
            }

            return ldapUser;
        }
    }


}
