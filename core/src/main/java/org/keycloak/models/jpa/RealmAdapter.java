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

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.entity.events.IdentityProviderRemovedEvent;
import com.hsbc.unified.iam.entity.events.IdentityProviderUpdatedEvent;
import com.hsbc.unified.iam.facade.model.JpaModel;
import com.hsbc.unified.iam.facade.spi.RealmFacade;
import com.hsbc.unified.iam.repository.*;
import com.hsbc.unified.iam.service.spi.RealmService;
import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.utils.ComponentUtil;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RealmAdapter implements RealmModel, JpaModel<Realm>, ApplicationEventPublisherAware {
    /**
     * This just exists for testing purposes
     */
    public static final String COMPONENT_PROVIDER_EXISTS_DISABLED = "component.provider.exists.disabled";
    private static final String BROWSER_HEADER_PREFIX = "_browser_header.";
    protected Realm realm;
    private PasswordPolicy passwordPolicy;
    private OTPPolicy otpPolicy;

    private ApplicationEventPublisher applicationEventPublisher;

    @Autowired
    private RoleAdapter roleAdapter;
    @Autowired
    private GroupAdapter groupAdapter;

    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private ClientScopeRepository clientScopeRepository;
    @Autowired
    private ClientScopeRoleMappingRepository clientScopeRoleMappingRepository;
    @Autowired
    private AuthenticationFlowRepository authenticationFlowRepository;
    @Autowired
    private AuthenticationExecutionRepository authenticationExecutionRepository;
    @Autowired
    private AuthenticatorConfigRepository authenticatorConfigRepository;
    @Autowired
    private DefaultClientScopeRealmMappingRepository defaultClientScopeRealmMappingRepository;
    @Autowired
    private ComponentRepository componentRepository;

    @Autowired
    private ClientScopeAdapter clientScopeAdapter;

    @Autowired
    private RealmService realmService;
    @Autowired
    private RealmRepository realmRepository;
    @Autowired
    private IdentityProviderRepository identityProviderRepository;
    @Autowired
    private IdentityProviderMapperRepository identityProviderMapperRepository;
    @Autowired
    private RequiredActionProviderRepository requiredActionProviderRepository;

    @Autowired
    private RealmFacade realmFacade;

    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private UserProvider userProvider;

    public RealmAdapter(Realm realm) {
        this.realm = realm;
    }

    public static boolean contains(String str, String[] array) {
        for (String s : array) {
            if (str.equals(s)) return true;
        }
        return false;
    }

    @Override
    public Long getClientsCount() {
        return clientRepository.getRealmClientsCount(this.getId());
    }

    public Realm getEntity() {
        return realm;
    }

    @Override
    public String getId() {
        return this.realmService.getId(realm);
    }

    @Override
    public String getName() {
        return this.realmService.getName(realm);
    }

    @Override
    public void setName(String name) {
        this.realmService.setName(realm, name);
    }

    @Override
    public String getDisplayName() {
        return this.realmService.getAttribute(realm, RealmAttribute.DISPLAY_NAME);
    }

    @Override
    public void setDisplayName(String displayName) {
        this.realmService.setAttribute(realm, RealmAttribute.DISPLAY_NAME, displayName);
    }

    @Override
    public String getDisplayNameHtml() {
        return this.realmService.getDisplayNameHtml(realm);
    }

    @Override
    public void setDisplayNameHtml(String displayNameHtml) {
        this.realmService.setDisplayNameHtml(realm, displayNameHtml);
    }

    @Override
    public boolean isEnabled() {
        return this.realmService.isEnabled(realm);
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.realmService.setEnabled(realm, enabled);
    }

    @Override
    public SslRequired getSslRequired() {
        return this.realmService.getSslRequired(realm);
    }

    @Override
    public void setSslRequired(SslRequired sslRequired) {
        this.realmService.setSslRequired(realm, sslRequired);
    }

    @Override
    public boolean isUserManagedAccessAllowed() {
        return this.realmService.isUserManagedAccessAllowed(realm);
    }

    @Override
    public void setUserManagedAccessAllowed(boolean userManagedAccessAllowed) {
        this.realmService.setUserManagedAccessAllowed(realm, userManagedAccessAllowed);
    }

    @Override
    public boolean isRegistrationAllowed() {
        return realmService.isRegistrationAllowed(realm);
    }

    @Override
    public void setRegistrationAllowed(boolean registrationAllowed) {
        realmService.setRegistrationAllowed(realm, registrationAllowed);
    }

    @Override
    public boolean isRegistrationEmailAsUsername() {
        return realmService.isRegistrationEmailAsUsername(realm);
    }

    @Override
    public void setRegistrationEmailAsUsername(boolean registrationEmailAsUsername) {
        realmService.setRegistrationEmailAsUsername(realm, registrationEmailAsUsername);
    }

    @Override
    public boolean isRememberMe() {
        return realmService.isRememberMe(realm);
    }

    @Override
    public void setRememberMe(boolean rememberMe) {
        realmService.setRememberMe(realm, rememberMe);
    }

    @Override
    public void setAttribute(String name, String value) {
        this.realmService.setAttribute(realm, name, value);
    }

    @Override
    public void setAttribute(String name, Boolean value) {
        this.realmService.setAttribute(realm, name, value);
    }

    @Override
    public void setAttribute(String name, Integer value) {
        this.realmService.setAttribute(realm, name, value);
    }

    @Override
    public void setAttribute(String name, Long value) {
        this.realmService.setAttribute(realm, name, value);
    }

    @Override
    public void removeAttribute(String name) {
        this.realmService.removeAttribute(realm, name);
    }

    @Override
    public String getAttribute(String name) {
        return this.realmService.getAttribute(realm, name);
    }

    @Override
    public Integer getAttribute(String name, Integer defaultValue) {
        return this.realmService.getAttribute(realm, name, defaultValue);
    }

    @Override
    public Long getAttribute(String name, Long defaultValue) {
        return this.realmService.getAttribute(realm, name, defaultValue);
    }

    @Override
    public Boolean getAttribute(String name, Boolean defaultValue) {
        return this.realmService.getAttribute(realm, name, defaultValue);
    }

    @Override
    public Map<String, String> getAttributes() {
        return this.realmService.getAttributes(realm);
    }

    @Override
    public String getDefaultSignatureAlgorithm() {
        return getAttribute("defaultSignatureAlgorithm");
    }

    @Override
    public void setDefaultSignatureAlgorithm(String defaultSignatureAlgorithm) {
        setAttribute("defaultSignatureAlgorithm", defaultSignatureAlgorithm);
    }

    @Override
    public boolean isBruteForceProtected() {
        return getAttribute("bruteForceProtected", false);
    }

    @Override
    public void setBruteForceProtected(boolean value) {
        setAttribute("bruteForceProtected", value);
    }

    @Override
    public boolean isPermanentLockout() {
        return getAttribute("permanentLockout", false);
    }

    @Override
    public void setPermanentLockout(final boolean val) {
        setAttribute("permanentLockout", val);
    }

    @Override
    public int getMaxFailureWaitSeconds() {
        return getAttribute("maxFailureWaitSeconds", 0);
    }

    @Override
    public void setMaxFailureWaitSeconds(int val) {
        setAttribute("maxFailureWaitSeconds", val);
    }

    @Override
    public int getWaitIncrementSeconds() {
        return getAttribute("waitIncrementSeconds", 0);
    }

    @Override
    public void setWaitIncrementSeconds(int val) {
        setAttribute("waitIncrementSeconds", val);
    }

    @Override
    public long getQuickLoginCheckMilliSeconds() {
        return getAttribute("quickLoginCheckMilliSeconds", 0L);
    }

    @Override
    public void setQuickLoginCheckMilliSeconds(long val) {
        setAttribute("quickLoginCheckMilliSeconds", val);
    }

    @Override
    public int getMinimumQuickLoginWaitSeconds() {
        return getAttribute("minimumQuickLoginWaitSeconds", 0);
    }

    @Override
    public void setMinimumQuickLoginWaitSeconds(int val) {
        setAttribute("minimumQuickLoginWaitSeconds", val);
    }

    @Override
    public int getMaxDeltaTimeSeconds() {
        return getAttribute("maxDeltaTimeSeconds", 0);
    }

    @Override
    public void setMaxDeltaTimeSeconds(int val) {
        setAttribute("maxDeltaTimeSeconds", val);
    }

    @Override
    public int getFailureFactor() {
        return getAttribute("failureFactor", 0);
    }

    @Override
    public void setFailureFactor(int failureFactor) {
        setAttribute("failureFactor", failureFactor);
    }

    @Override
    public boolean isVerifyEmail() {
        return realmService.isVerifyEmail(realm);
    }

    @Override
    public void setVerifyEmail(boolean verifyEmail) {
        realmService.setVerifyEmail(realm, verifyEmail);
    }

    @Override
    public boolean isLoginWithEmailAllowed() {
        return realmService.isLoginWithEmailAllowed(realm);
    }

    @Override
    public void setLoginWithEmailAllowed(boolean loginWithEmailAllowed) {
        realmService.setLoginWithEmailAllowed(realm, loginWithEmailAllowed);
    }

    @Override
    public boolean isDuplicateEmailsAllowed() {
        return realmService.isDuplicateEmailsAllowed(realm);
    }

    @Override
    public void setDuplicateEmailsAllowed(boolean duplicateEmailsAllowed) {
        realmService.setDuplicateEmailsAllowed(realm, duplicateEmailsAllowed);
    }

    @Override
    public boolean isResetPasswordAllowed() {
        return realmService.isResetPasswordAllowed(realm);
    }

    @Override
    public void setResetPasswordAllowed(boolean resetPasswordAllowed) {
        realmService.setResetPasswordAllowed(realm, resetPasswordAllowed);
    }

    @Override
    public boolean isEditUsernameAllowed() {
        return realmService.isEditUsernameAllowed(realm);
    }

    @Override
    public void setEditUsernameAllowed(boolean editUsernameAllowed) {
        realmService.setEditUsernameAllowed(realm, editUsernameAllowed);
    }

    @Override
    public int getNotBefore() {
        return realmService.getNotBefore(realm);
    }

    @Override
    public void setNotBefore(int notBefore) {
        realmService.setNotBefore(realm, notBefore);
    }

    @Override
    public boolean isRevokeRefreshToken() {
        return realmService.isRevokeRefreshToken(realm);
    }

    @Override
    public void setRevokeRefreshToken(boolean revokeRefreshToken) {
        realmService.setRevokeRefreshToken(realm, revokeRefreshToken);
    }

    @Override
    public int getRefreshTokenMaxReuse() {
        return realmService.getRefreshTokenMaxReuse(realm);
    }

    @Override
    public void setRefreshTokenMaxReuse(int revokeRefreshTokenReuseCount) {
        realmService.setRefreshTokenMaxReuse(realm, revokeRefreshTokenReuseCount);
    }

    @Override
    public int getAccessTokenLifespan() {
        return realmService.getAccessTokenLifespan(realm);
    }

    @Override
    public void setAccessTokenLifespan(int tokenLifespan) {
        realmService.setAccessTokenLifespan(realm, tokenLifespan);
    }

    @Override
    public int getAccessTokenLifespanForImplicitFlow() {
        return realmService.getAccessTokenLifespanForImplicitFlow(realm);
    }

    @Override
    public void setAccessTokenLifespanForImplicitFlow(int seconds) {
        realmService.setAccessTokenLifespanForImplicitFlow(realm, seconds);
    }

    @Override
    public int getSsoSessionIdleTimeout() {
        return realmService.getSsoSessionIdleTimeout(realm);
    }

    @Override
    public void setSsoSessionIdleTimeout(int seconds) {
        realmService.setSsoSessionIdleTimeout(realm, seconds);
    }

    @Override
    public int getSsoSessionMaxLifespan() {
        return realmService.getSsoSessionMaxLifespan(realm);
    }

    @Override
    public void setSsoSessionMaxLifespan(int seconds) {
        realmService.setSsoSessionMaxLifespan(realm, seconds);
    }

    @Override
    public int getSsoSessionIdleTimeoutRememberMe() {
        return realmService.getSsoSessionIdleTimeoutRememberMe(realm);
    }

    @Override
    public void setSsoSessionIdleTimeoutRememberMe(int seconds) {
        realmService.setSsoSessionIdleTimeoutRememberMe(realm, seconds);
    }

    @Override
    public int getSsoSessionMaxLifespanRememberMe() {
        return realmService.getSsoSessionMaxLifespanRememberMe(realm);
    }

    @Override
    public void setSsoSessionMaxLifespanRememberMe(int seconds) {
        realmService.setSsoSessionMaxLifespanRememberMe(realm, seconds);
    }

    @Override
    public int getOfflineSessionIdleTimeout() {
        return realmService.getOfflineSessionIdleTimeout(realm);
    }

    @Override
    public void setOfflineSessionIdleTimeout(int seconds) {
        realmService.setOfflineSessionIdleTimeout(realm, seconds);
    }

    @Override
    public boolean isOfflineSessionMaxLifespanEnabled() {
        return realmService.getAttribute(realm, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN_ENABLED, false);
    }

    @Override
    public void setOfflineSessionMaxLifespanEnabled(boolean offlineSessionMaxLifespanEnabled) {
        realmService.setAttribute(realm, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN_ENABLED, offlineSessionMaxLifespanEnabled);
    }

    @Override
    public int getOfflineSessionMaxLifespan() {
        return realmService.getAttribute(realm, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN, Constants.DEFAULT_OFFLINE_SESSION_MAX_LIFESPAN);
    }

    @Override
    public void setOfflineSessionMaxLifespan(int seconds) {
        realmService.setAttribute(realm, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN, seconds);
    }

    @Override
    public int getAccessCodeLifespan() {
        return realmService.getAccessCodeLifespan(realm);
    }

    @Override
    public void setAccessCodeLifespan(int accessCodeLifespan) {
        realmService.setAccessCodeLifespan(realm, accessCodeLifespan);
    }

    @Override
    public int getAccessCodeLifespanUserAction() {
        return realmService.getAccessCodeLifespanUserAction(realm);
    }

    @Override
    public void setAccessCodeLifespanUserAction(int accessCodeLifespanUserAction) {
        realmService.setAccessCodeLifespanUserAction(realm, accessCodeLifespanUserAction);
    }

    @Override
    public Map<String, Integer> getUserActionTokenLifespans() {
        return realmService.getUserActionTokenLifespans(realm);
    }

    @Override
    public int getAccessCodeLifespanLogin() {
        return realmService.getAccessCodeLifespanLogin(realm);
    }

    @Override
    public void setAccessCodeLifespanLogin(int accessCodeLifespanLogin) {
        realmService.setAccessCodeLifespanLogin(realm, accessCodeLifespanLogin);
    }

    @Override
    public int getActionTokenGeneratedByAdminLifespan() {
        return realmService.getAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN, 12 * 60 * 60);
    }

    @Override
    public void setActionTokenGeneratedByAdminLifespan(int actionTokenGeneratedByAdminLifespan) {
        realmService.setAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN, actionTokenGeneratedByAdminLifespan);
    }

    @Override
    public int getActionTokenGeneratedByUserLifespan() {
        return realmService.getAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN, getAccessCodeLifespanUserAction());
    }

    @Override
    public void setActionTokenGeneratedByUserLifespan(int actionTokenGeneratedByUserLifespan) {
        realmService.setAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN, actionTokenGeneratedByUserLifespan);
    }

    @Override
    public int getActionTokenGeneratedByUserLifespan(String actionTokenId) {
        if (actionTokenId == null || realmService.getAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + "." + actionTokenId) == null) {
            return realmService.getActionTokenGeneratedByUserLifespan(realm);
        }

        return realmService.getAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + "." + actionTokenId, getAccessCodeLifespanUserAction());
    }

    @Override
    public void setActionTokenGeneratedByUserLifespan(String actionTokenId, Integer actionTokenGeneratedByUserLifespan) {
        if (actionTokenGeneratedByUserLifespan != null) {
            realmService.setAttribute(realm, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + "." + actionTokenId, actionTokenGeneratedByUserLifespan);
        }
    }

    @Override
    public void addRequiredCredential(String type) {
        realmFacade.addRequiredCredential(realm, type);
    }

    @Override
    public void updateRequiredCredentials(Set<String> credentials) {
        realmFacade.updateRequiredCredentials(realm, credentials);
    }

    @Override
    public List<RequiredCredentialModel> getRequiredCredentials() {
        return realmFacade.getRequiredCredentials(realm);
    }

    @Override
    public List<String> getDefaultRoles() {
        return realmFacade.getDefaultRoles(realm);
    }

    @Override
    public void addDefaultRole(String name) {
        RoleModel role = getRole(name);
        if (role == null) {
            role = addRole(name);
        }
        Collection<Role> entities = realm.getDefaultRoles();
        for (Role entity : entities) {
            if (entity.getId().equals(role.getId())) {
                return;
            }
        }
        Role roleEntity = roleAdapter.toRoleEntity(role);
        entities.add(roleEntity);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public void updateDefaultRoles(String[] defaultRoles) {
        Collection<Role> entities = realm.getDefaultRoles();
        Set<String> already = new HashSet<>();
        List<Role> remove = new ArrayList<>();
        for (Role rel : entities) {
            if (!contains(rel.getName(), defaultRoles)) {
                remove.add(rel);
            } else {
                already.add(rel.getName());
            }
        }
        for (Role entity : remove) {
            entities.remove(entity);
        }
        realmRepository.saveAndFlush(realm);
        for (String roleName : defaultRoles) {
            if (!already.contains(roleName)) {
                addDefaultRole(roleName);
            }
        }
    }

    @Override
    public void removeDefaultRoles(String... defaultRoles) {
        Collection<Role> entities = realm.getDefaultRoles();
        List<Role> remove = new ArrayList<>();
        for (Role rel : entities) {
            if (contains(rel.getName(), defaultRoles)) {
                remove.add(rel);
            }
        }
        for (Role entity : remove) {
            entities.remove(entity);
        }
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public List<GroupModel> getDefaultGroups() {
        Collection<Group> entities = realm.getDefaultGroups();
        if (entities == null || entities.isEmpty()) return Collections.EMPTY_LIST;
        List<GroupModel> defaultGroups = new LinkedList<>();
        for (Group entity : entities) {
            defaultGroups.add(realmProvider.getGroupById(entity.getId(), this));
        }
        return Collections.unmodifiableList(defaultGroups);
    }

    @Override
    public void addDefaultGroup(GroupModel group) {
        Collection<Group> entities = realm.getDefaultGroups();
        for (Group entity : entities) {
            if (entity.getId().equals(group.getId())) return;
        }
        Group groupEntity = groupAdapter.toEntity(group);
        realm.getDefaultGroups().add(groupEntity);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public void removeDefaultGroup(GroupModel group) {
        Group found = null;
        for (Group defaultGroup : realm.getDefaultGroups()) {
            if (defaultGroup.getId().equals(group.getId())) {
                found = defaultGroup;
                break;
            }
        }
        if (found != null) {
            realm.getDefaultGroups().remove(found);
            realmRepository.saveAndFlush(realm);
        }
    }

    @Override
    public List<ClientModel> getClients() {
        return realmProvider.getClients(this);
    }

    @Override
    public List<ClientModel> getClients(Integer firstResult, Integer maxResults) {
        return realmProvider.getClients(this, firstResult, maxResults);
    }

    @Override
    public List<ClientModel> getAlwaysDisplayInConsoleClients() {
        return realmProvider.getAlwaysDisplayInConsoleClients(this);
    }

    @Override
    public ClientModel addClient(String name) {
        return realmProvider.addClient(this, name);
    }

    @Override
    public ClientModel addClient(String id, String clientId) {
        return realmProvider.addClient(this, id, clientId);
    }

    @Override
    public boolean removeClient(String id) {
        if (id == null) return false;
        ClientModel client = getClientById(id);
        if (client == null) return false;
        return realmProvider.removeClient(id, this);
    }

    @Override
    public ClientModel getClientById(String id) {
        return realmProvider.getClientById(id, this);
    }

    @Override
    public ClientModel getClientByClientId(String clientId) {
        return realmProvider.getClientByClientId(clientId, this);
    }

    @Override
    public List<ClientModel> searchClientByClientId(String clientId, Integer firstResult, Integer maxResults) {
        return realmProvider.searchClientsByClientId(clientId, firstResult, maxResults, this);
    }

    @Override
    public Map<String, String> getBrowserSecurityHeaders() {
        Map<String, String> attributes = getAttributes();
        if (attributes.isEmpty()) return Collections.EMPTY_MAP;
        Map<String, String> headers = new HashMap<String, String>();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (entry.getKey().startsWith(BROWSER_HEADER_PREFIX)) {
                headers.put(entry.getKey().substring(BROWSER_HEADER_PREFIX.length()), entry.getValue());
            }
        }
        return Collections.unmodifiableMap(headers);
    }

    @Override
    public void setBrowserSecurityHeaders(Map<String, String> headers) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            setAttribute(BROWSER_HEADER_PREFIX + entry.getKey(), entry.getValue());
        }
    }

    @Override
    public Map<String, String> getSmtpConfig() {
        Map<String, String> config = new HashMap<>();
        config.putAll(realm.getSmtpConfig());
        return Collections.unmodifiableMap(config);
    }

    @Override
    public void setSmtpConfig(Map<String, String> smtpConfig) {
        realm.setSmtpConfig(smtpConfig);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public RoleModel getRole(String name) {
        return realmProvider.getRealmRole(this, name);
    }

    @Override
    public RoleModel addRole(String name) {
        return realmProvider.addRealmRole(this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return realmProvider.addRealmRole(this, id, name);
    }

    @Override
    public boolean removeRole(RoleModel role) {
        return realmProvider.removeRole(this, role);
    }

    @Override
    public Set<RoleModel> getRoles() {
        return realmProvider.getRealmRoles(this);
    }

    @Override
    public Set<RoleModel> getRoles(Integer first, Integer max) {
        return realmProvider.getRealmRoles(this, first, max);
    }

    @Override
    public Set<RoleModel> searchForRoles(String search, Integer first, Integer max) {
        return realmProvider.searchForRoles(this, search, first, max);
    }

    @Override
    public RoleModel getRoleById(String id) {
        return realmProvider.getRoleById(id, this);
    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        if (passwordPolicy == null) {
            passwordPolicy = passwordPolicy.parse(realm.getPasswordPolicy());
        }
        return passwordPolicy;
    }

    @Override
    public void setPasswordPolicy(PasswordPolicy policy) {
        this.passwordPolicy = policy;
        realm.setPasswordPolicy(policy.toString());
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public OTPPolicy getOTPPolicy() {
        if (otpPolicy == null) {
            otpPolicy = new OTPPolicy();
            otpPolicy.setDigits(realm.getOtpPolicyDigits());
            otpPolicy.setAlgorithm(realm.getOtpPolicyAlgorithm());
            otpPolicy.setInitialCounter(realm.getOtpPolicyInitialCounter());
            otpPolicy.setLookAheadWindow(realm.getOtpPolicyLookAheadWindow());
            otpPolicy.setType(realm.getOtpPolicyType());
            otpPolicy.setPeriod(realm.getOtpPolicyPeriod());
        }
        return otpPolicy;
    }


    // WebAuthn

    @Override
    public void setOTPPolicy(OTPPolicy policy) {
        realm.setOtpPolicyAlgorithm(policy.getAlgorithm());
        realm.setOtpPolicyDigits(policy.getDigits());
        realm.setOtpPolicyInitialCounter(policy.getInitialCounter());
        realm.setOtpPolicyLookAheadWindow(policy.getLookAheadWindow());
        realm.setOtpPolicyType(policy.getType());
        realm.setOtpPolicyPeriod(policy.getPeriod());
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public WebAuthnPolicy getWebAuthnPolicy() {
        return getWebAuthnPolicy("");
    }

    @Override
    public void setWebAuthnPolicy(WebAuthnPolicy policy) {
        setWebAuthnPolicy(policy, "");
    }

    @Override
    public WebAuthnPolicy getWebAuthnPolicyPasswordless() {
        // We will use some prefix for attributes related to passwordless WebAuthn policy
        return getWebAuthnPolicy(Constants.WEBAUTHN_PASSWORDLESS_PREFIX);
    }

    @Override
    public void setWebAuthnPolicyPasswordless(WebAuthnPolicy policy) {
        // We will use some prefix for attributes related to passwordless WebAuthn policy
        setWebAuthnPolicy(policy, Constants.WEBAUTHN_PASSWORDLESS_PREFIX);
    }

    private WebAuthnPolicy getWebAuthnPolicy(String attributePrefix) {
        WebAuthnPolicy policy = new WebAuthnPolicy();

        // mandatory parameters
        String rpEntityName = getAttribute(RealmAttribute.WEBAUTHN_POLICY_RP_ENTITY_NAME + attributePrefix);
        if (rpEntityName == null || rpEntityName.isEmpty())
            rpEntityName = Constants.DEFAULT_WEBAUTHN_POLICY_RP_ENTITY_NAME;
        policy.setRpEntityName(rpEntityName);

        String signatureAlgorithmsString = getAttribute(RealmAttribute.WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS + attributePrefix);
        if (signatureAlgorithmsString == null || signatureAlgorithmsString.isEmpty())
            signatureAlgorithmsString = Constants.DEFAULT_WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS;
        List<String> signatureAlgorithms = Arrays.asList(signatureAlgorithmsString.split(","));
        policy.setSignatureAlgorithm(signatureAlgorithms);

        // optional parameters
        String rpId = getAttribute(RealmAttribute.WEBAUTHN_POLICY_RP_ID + attributePrefix);
        if (rpId == null || rpId.isEmpty()) rpId = "";
        policy.setRpId(rpId);

        String attestationConveyancePreference = getAttribute(RealmAttribute.WEBAUTHN_POLICY_ATTESTATION_CONVEYANCE_PREFERENCE + attributePrefix);
        if (attestationConveyancePreference == null || attestationConveyancePreference.isEmpty())
            attestationConveyancePreference = Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED;
        policy.setAttestationConveyancePreference(attestationConveyancePreference);

        String authenticatorAttachment = getAttribute(RealmAttribute.WEBAUTHN_POLICY_AUTHENTICATOR_ATTACHMENT + attributePrefix);
        if (authenticatorAttachment == null || authenticatorAttachment.isEmpty())
            authenticatorAttachment = Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED;
        policy.setAuthenticatorAttachment(authenticatorAttachment);

        String requireResidentKey = getAttribute(RealmAttribute.WEBAUTHN_POLICY_REQUIRE_RESIDENT_KEY + attributePrefix);
        if (requireResidentKey == null || requireResidentKey.isEmpty())
            requireResidentKey = Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED;
        policy.setRequireResidentKey(requireResidentKey);

        String userVerificationRequirement = getAttribute(RealmAttribute.WEBAUTHN_POLICY_USER_VERIFICATION_REQUIREMENT + attributePrefix);
        if (userVerificationRequirement == null || userVerificationRequirement.isEmpty())
            userVerificationRequirement = Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED;
        policy.setUserVerificationRequirement(userVerificationRequirement);

        String createTime = getAttribute(RealmAttribute.WEBAUTHN_POLICY_CREATE_TIMEOUT + attributePrefix);
        if (createTime != null) policy.setCreateTimeout(Integer.parseInt(createTime));
        else policy.setCreateTimeout(0);

        String avoidSameAuthenticatorRegister = getAttribute(RealmAttribute.WEBAUTHN_POLICY_AVOID_SAME_AUTHENTICATOR_REGISTER + attributePrefix);
        if (avoidSameAuthenticatorRegister != null)
            policy.setAvoidSameAuthenticatorRegister(Boolean.parseBoolean(avoidSameAuthenticatorRegister));

        String acceptableAaguidsString = getAttribute(RealmAttribute.WEBAUTHN_POLICY_ACCEPTABLE_AAGUIDS + attributePrefix);
        List<String> acceptableAaguids = new ArrayList<>();
        if (acceptableAaguidsString != null && !acceptableAaguidsString.isEmpty())
            acceptableAaguids = Arrays.asList(acceptableAaguidsString.split(","));
        policy.setAcceptableAaguids(acceptableAaguids);

        return policy;
    }

    private void setWebAuthnPolicy(WebAuthnPolicy policy, String attributePrefix) {
        // mandatory parameters
        String rpEntityName = policy.getRpEntityName();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_RP_ENTITY_NAME + attributePrefix, rpEntityName);

        List<String> signatureAlgorithms = policy.getSignatureAlgorithm();
        String signatureAlgorithmsString = String.join(",", signatureAlgorithms);
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS + attributePrefix, signatureAlgorithmsString);

        // optional parameters
        String rpId = policy.getRpId();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_RP_ID + attributePrefix, rpId);

        String attestationConveyancePreference = policy.getAttestationConveyancePreference();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_ATTESTATION_CONVEYANCE_PREFERENCE + attributePrefix, attestationConveyancePreference);

        String authenticatorAttachment = policy.getAuthenticatorAttachment();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_AUTHENTICATOR_ATTACHMENT + attributePrefix, authenticatorAttachment);

        String requireResidentKey = policy.getRequireResidentKey();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_REQUIRE_RESIDENT_KEY + attributePrefix, requireResidentKey);

        String userVerificationRequirement = policy.getUserVerificationRequirement();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_USER_VERIFICATION_REQUIREMENT + attributePrefix, userVerificationRequirement);

        int createTime = policy.getCreateTimeout();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_CREATE_TIMEOUT + attributePrefix, Integer.toString(createTime));

        boolean avoidSameAuthenticatorRegister = policy.isAvoidSameAuthenticatorRegister();
        setAttribute(RealmAttribute.WEBAUTHN_POLICY_AVOID_SAME_AUTHENTICATOR_REGISTER + attributePrefix, Boolean.toString(avoidSameAuthenticatorRegister));

        List<String> acceptableAaguids = policy.getAcceptableAaguids();
        if (acceptableAaguids != null && !acceptableAaguids.isEmpty()) {
            String acceptableAaguidsString = String.join(",", acceptableAaguids);
            setAttribute(RealmAttribute.WEBAUTHN_POLICY_ACCEPTABLE_AAGUIDS + attributePrefix, acceptableAaguidsString);
        } else {
            removeAttribute(RealmAttribute.WEBAUTHN_POLICY_ACCEPTABLE_AAGUIDS + attributePrefix);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof RealmModel)) return false;

        RealmModel that = (RealmModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    @Override
    public String getLoginTheme() {
        return realm.getLoginTheme();
    }

    @Override
    public void setLoginTheme(String name) {
        realm.setLoginTheme(name);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public String getAccountTheme() {
        return realm.getAccountTheme();
    }

    @Override
    public void setAccountTheme(String name) {
        realm.setAccountTheme(name);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public String getAdminTheme() {
        return realm.getAdminTheme();
    }

    @Override
    public void setAdminTheme(String name) {
        realm.setAdminTheme(name);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public String getEmailTheme() {
        return realm.getEmailTheme();
    }

    @Override
    public void setEmailTheme(String name) {
        realm.setEmailTheme(name);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public boolean isEventsEnabled() {
        return realm.isEventsEnabled();
    }

    @Override
    public void setEventsEnabled(boolean enabled) {
        realm.setEventsEnabled(enabled);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public long getEventsExpiration() {
        return realm.getEventsExpiration();
    }

    @Override
    public void setEventsExpiration(long expiration) {
        realm.setEventsExpiration(expiration);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public Set<String> getEventsListeners() {
        Set<String> eventsListeners = realm.getEventsListeners();
        if (eventsListeners.isEmpty()) return Collections.EMPTY_SET;
        Set<String> copy = new HashSet<>();
        copy.addAll(eventsListeners);
        return Collections.unmodifiableSet(copy);
    }

    @Override
    public void setEventsListeners(Set<String> listeners) {
        realm.setEventsListeners(listeners);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public Set<String> getEnabledEventTypes() {
        Set<String> enabledEventTypes = realm.getEnabledEventTypes();
        if (enabledEventTypes.isEmpty()) return Collections.EMPTY_SET;
        Set<String> copy = new HashSet<>();
        copy.addAll(enabledEventTypes);
        return Collections.unmodifiableSet(copy);
    }

    @Override
    public void setEnabledEventTypes(Set<String> enabledEventTypes) {
        realm.setEnabledEventTypes(enabledEventTypes);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public boolean isAdminEventsEnabled() {
        return realm.isAdminEventsEnabled();
    }

    @Override
    public void setAdminEventsEnabled(boolean enabled) {
        realm.setAdminEventsEnabled(enabled);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public boolean isAdminEventsDetailsEnabled() {
        return realm.isAdminEventsDetailsEnabled();
    }

    @Override
    public void setAdminEventsDetailsEnabled(boolean enabled) {
        realm.setAdminEventsDetailsEnabled(enabled);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public ClientModel getMasterAdminClient() {
        Client masterAdminClient = realm.getMasterAdminClient();
        if (masterAdminClient == null) {
            return null;
        }
        RealmModel masterRealm = null;
        String masterAdminClientRealmId = masterAdminClient.getRealm().getId();
        if (masterAdminClientRealmId.equals(getId())) {
            masterRealm = this;
        } else {
            masterRealm = realmProvider.getRealm(masterAdminClientRealmId);
        }
        return realmProvider.getClientById(masterAdminClient.getId(), masterRealm);
    }

    @Override
    public void setMasterAdminClient(ClientModel client) {
        Client appEntity = client != null ? clientRepository.getOne(client.getId()) : null;
        realm.setMasterAdminClient(appEntity);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public List<IdentityProviderModel> getIdentityProviders() {
        List<IdentityProvider> entities = realm.getIdentityProviders();
        if (entities.isEmpty()) return Collections.EMPTY_LIST;
        List<IdentityProviderModel> identityProviders = new ArrayList<>();

        for (IdentityProvider entity : entities) {
            IdentityProviderModel identityProviderModel = entityToModel(entity);

            identityProviders.add(identityProviderModel);
        }

        return Collections.unmodifiableList(identityProviders);
    }

    private IdentityProviderModel entityToModel(IdentityProvider entity) {
        IdentityProviderModel identityProviderModel = new IdentityProviderModel();
        identityProviderModel.setProviderId(entity.getProviderId());
        identityProviderModel.setAlias(entity.getAlias());
        identityProviderModel.setDisplayName(entity.getDisplayName());

        identityProviderModel.setInternalId(entity.getInternalId());
        Map<String, String> config = entity.getConfig();
        Map<String, String> copy = new HashMap<>(config);
        identityProviderModel.setConfig(copy);
        identityProviderModel.setEnabled(entity.isEnabled());
        identityProviderModel.setLinkOnly(entity.isLinkOnly());
        identityProviderModel.setTrustEmail(entity.isTrustEmail());
        identityProviderModel.setAuthenticateByDefault(entity.isAuthenticateByDefault());
        identityProviderModel.setFirstBrokerLoginFlowId(entity.getFirstBrokerLoginFlowId());
        identityProviderModel.setPostBrokerLoginFlowId(entity.getPostBrokerLoginFlowId());
        identityProviderModel.setStoreToken(entity.isStoreToken());
        identityProviderModel.setAddReadTokenRoleOnCreate(entity.isAddReadTokenRoleOnCreate());
        return identityProviderModel;
    }

    @Override
    public IdentityProviderModel getIdentityProviderByAlias(String alias) {
        for (IdentityProviderModel identityProviderModel : getIdentityProviders()) {
            if (identityProviderModel.getAlias().equals(alias)) {
                return identityProviderModel;
            }
        }

        return null;
    }

    @Override
    public void addIdentityProvider(IdentityProviderModel identityProvider) {
        IdentityProvider entity = new IdentityProvider();

        if (identityProvider.getInternalId() == null) {
            entity.setInternalId(KeycloakModelUtils.generateId());
        } else {
            entity.setInternalId(identityProvider.getInternalId());
        }
        entity.setAlias(identityProvider.getAlias());
        entity.setDisplayName(identityProvider.getDisplayName());
        entity.setProviderId(identityProvider.getProviderId());
        entity.setEnabled(identityProvider.isEnabled());
        entity.setStoreToken(identityProvider.isStoreToken());
        entity.setAddReadTokenRoleOnCreate(identityProvider.isAddReadTokenRoleOnCreate());
        entity.setTrustEmail(identityProvider.isTrustEmail());
        entity.setAuthenticateByDefault(identityProvider.isAuthenticateByDefault());
        entity.setFirstBrokerLoginFlowId(identityProvider.getFirstBrokerLoginFlowId());
        entity.setPostBrokerLoginFlowId(identityProvider.getPostBrokerLoginFlowId());
        entity.setConfig(identityProvider.getConfig());
        entity.setLinkOnly(identityProvider.isLinkOnly());

        realm.addIdentityProvider(entity);

        identityProvider.setInternalId(entity.getInternalId());

        realmRepository.saveAndFlush(realm);
    }

    @Override
    public void removeIdentityProviderByAlias(String alias) {
        for (IdentityProvider entity : realm.getIdentityProviders()) {
            if (entity.getAlias().equals(alias)) {
                IdentityProviderModel model = entityToModel(entity);
                identityProviderRepository.delete(entity);

                applicationEventPublisher.publishEvent(new IdentityProviderRemovedEvent(model));
            }
        }
    }

    @Override
    public void updateIdentityProvider(IdentityProviderModel identityProvider) {
        for (IdentityProvider entity : this.realm.getIdentityProviders()) {
            if (entity.getInternalId().equals(identityProvider.getInternalId())) {
                entity.setAlias(identityProvider.getAlias());
                entity.setDisplayName(identityProvider.getDisplayName());
                entity.setEnabled(identityProvider.isEnabled());
                entity.setTrustEmail(identityProvider.isTrustEmail());
                entity.setAuthenticateByDefault(identityProvider.isAuthenticateByDefault());
                entity.setFirstBrokerLoginFlowId(identityProvider.getFirstBrokerLoginFlowId());
                entity.setPostBrokerLoginFlowId(identityProvider.getPostBrokerLoginFlowId());
                entity.setAddReadTokenRoleOnCreate(identityProvider.isAddReadTokenRoleOnCreate());
                entity.setStoreToken(identityProvider.isStoreToken());
                entity.setConfig(identityProvider.getConfig());
                entity.setLinkOnly(identityProvider.isLinkOnly());
            }
        }

        realmRepository.saveAndFlush(realm);

        applicationEventPublisher.publishEvent(new IdentityProviderUpdatedEvent(identityProvider));
    }

    @Override
    public boolean isIdentityFederationEnabled() {
        return !this.realm.getIdentityProviders().isEmpty();
    }

    @Override
    public boolean isInternationalizationEnabled() {
        return realm.isInternationalizationEnabled();
    }

    @Override
    public void setInternationalizationEnabled(boolean enabled) {
        realm.setInternationalizationEnabled(enabled);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public Set<String> getSupportedLocales() {
        Set<String> supportedLocales = realm.getSupportedLocales();
        if (supportedLocales == null || supportedLocales.isEmpty()) return Collections.EMPTY_SET;
        Set<String> copy = new HashSet<>(supportedLocales);
        return Collections.unmodifiableSet(copy);
    }

    @Override
    public void setSupportedLocales(Set<String> locales) {
        realm.setSupportedLocales(locales);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public String getDefaultLocale() {
        return realm.getDefaultLocale();
    }

    @Override
    public void setDefaultLocale(String locale) {
        realm.setDefaultLocale(locale);
        realmRepository.saveAndFlush(realm);
    }

    @Override
    public Set<IdentityProviderMapperModel> getIdentityProviderMappers() {
        Collection<IdentityProviderMapper> entities = this.realm.getIdentityProviderMappers();
        if (entities.isEmpty()) return Collections.EMPTY_SET;
        Set<IdentityProviderMapperModel> mappings = new HashSet<>();
        for (IdentityProviderMapper entity : entities) {
            IdentityProviderMapperModel mapping = entityToModel(entity);
            mappings.add(mapping);
        }
        return Collections.unmodifiableSet(mappings);
    }

    @Override
    public Set<IdentityProviderMapperModel> getIdentityProviderMappersByAlias(String brokerAlias) {
        Set<IdentityProviderMapperModel> mappings = new HashSet<>();
        for (IdentityProviderMapper entity : this.realm.getIdentityProviderMappers()) {
            if (!entity.getIdentityProviderAlias().equals(brokerAlias)) {
                continue;
            }
            IdentityProviderMapperModel mapping = entityToModel(entity);
            mappings.add(mapping);
        }
        return mappings;
    }

    @Override
    public IdentityProviderMapperModel addIdentityProviderMapper(IdentityProviderMapperModel model) {
        if (getIdentityProviderMapperByName(model.getIdentityProviderAlias(), model.getName()) != null) {
            throw new RuntimeException("identity provider mapper name must be unique per identity provider");
        }
        String id = KeycloakModelUtils.generateId();
        IdentityProviderMapper entity = new IdentityProviderMapper();
        entity.setId(id);
        entity.setName(model.getName());
        entity.setIdentityProviderAlias(model.getIdentityProviderAlias());
        entity.setIdentityProviderMapper(model.getIdentityProviderMapper());
        entity.setRealm(this.realm);
        entity.setConfig(model.getConfig());

        identityProviderMapperRepository.saveAndFlush(entity);
        this.realm.getIdentityProviderMappers().add(entity);
        return entityToModel(entity);
    }

    protected IdentityProviderMapper getIdentityProviderMapperEntity(String id) {
        for (IdentityProviderMapper entity : this.realm.getIdentityProviderMappers()) {
            if (entity.getId().equals(id)) {
                return entity;
            }
        }
        return null;

    }

    protected IdentityProviderMapper getIdentityProviderMapperEntityByName(String alias, String name) {
        for (IdentityProviderMapper entity : this.realm.getIdentityProviderMappers()) {
            if (entity.getIdentityProviderAlias().equals(alias) && entity.getName().equals(name)) {
                return entity;
            }
        }
        return null;

    }

    @Override
    public void removeIdentityProviderMapper(IdentityProviderMapperModel mapping) {
        IdentityProviderMapper toDelete = getIdentityProviderMapperEntity(mapping.getId());
        if (toDelete != null) {
            this.realm.getIdentityProviderMappers().remove(toDelete);
            realmRepository.save(realm);
            identityProviderMapperRepository.delete(toDelete);
        }
    }

    @Override
    public void updateIdentityProviderMapper(IdentityProviderMapperModel mapping) {
        IdentityProviderMapper entity = getIdentityProviderMapperEntity(mapping.getId());
        entity.setIdentityProviderAlias(mapping.getIdentityProviderAlias());
        entity.setIdentityProviderMapper(mapping.getIdentityProviderMapper());
        if (entity.getConfig() == null) {
            entity.setConfig(mapping.getConfig());
        } else {
            entity.getConfig().clear();
            if (mapping.getConfig() != null) {
                entity.getConfig().putAll(mapping.getConfig());
            }
        }

        identityProviderMapperRepository.saveAndFlush(entity);
    }

    @Override
    public IdentityProviderMapperModel getIdentityProviderMapperById(String id) {
        IdentityProviderMapper entity = getIdentityProviderMapperEntity(id);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    @Override
    public IdentityProviderMapperModel getIdentityProviderMapperByName(String alias, String name) {
        IdentityProviderMapper entity = getIdentityProviderMapperEntityByName(alias, name);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    protected IdentityProviderMapperModel entityToModel(IdentityProviderMapper entity) {
        IdentityProviderMapperModel mapping = new IdentityProviderMapperModel();
        mapping.setId(entity.getId());
        mapping.setName(entity.getName());
        mapping.setIdentityProviderAlias(entity.getIdentityProviderAlias());
        mapping.setIdentityProviderMapper(entity.getIdentityProviderMapper());
        Map<String, String> config = new HashMap<String, String>();
        if (entity.getConfig() != null) config.putAll(entity.getConfig());
        mapping.setConfig(config);
        return mapping;
    }

    @Override
    public AuthenticationFlowModel getBrowserFlow() {
        String flowId = realm.getBrowserFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    @Override
    public void setBrowserFlow(AuthenticationFlowModel flow) {
        realm.setBrowserFlow(flow.getId());

    }

    @Override
    public AuthenticationFlowModel getRegistrationFlow() {
        String flowId = realm.getRegistrationFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    @Override
    public void setRegistrationFlow(AuthenticationFlowModel flow) {
        realm.setRegistrationFlow(flow.getId());

    }

    @Override
    public AuthenticationFlowModel getDirectGrantFlow() {
        String flowId = realm.getDirectGrantFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    @Override
    public void setDirectGrantFlow(AuthenticationFlowModel flow) {
        realm.setDirectGrantFlow(flow.getId());

    }

    @Override
    public AuthenticationFlowModel getResetCredentialsFlow() {
        String flowId = realm.getResetCredentialsFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    @Override
    public void setResetCredentialsFlow(AuthenticationFlowModel flow) {
        realm.setResetCredentialsFlow(flow.getId());
    }

    public AuthenticationFlowModel getClientAuthenticationFlow() {
        String flowId = realm.getClientAuthenticationFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    public void setClientAuthenticationFlow(AuthenticationFlowModel flow) {
        realm.setClientAuthenticationFlow(flow.getId());
    }

    @Override
    public AuthenticationFlowModel getDockerAuthenticationFlow() {
        String flowId = realm.getDockerAuthenticationFlow();
        if (flowId == null) return null;
        return getAuthenticationFlowById(flowId);
    }

    @Override
    public void setDockerAuthenticationFlow(AuthenticationFlowModel flow) {
        realm.setDockerAuthenticationFlow(flow.getId());
    }

    @Override
    public List<AuthenticationFlowModel> getAuthenticationFlows() {
        return realm.getAuthenticationFlows().stream()
                .map(this::entityToModel)
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(), Collections::unmodifiableList));
    }

    @Override
    public AuthenticationFlowModel getFlowByAlias(String alias) {
        for (AuthenticationFlowModel flow : getAuthenticationFlows()) {
            if (flow.getAlias().equals(alias)) {
                return flow;
            }
        }
        return null;
    }

    @Override
    public AuthenticatorConfigModel getAuthenticatorConfigByAlias(String alias) {
        for (AuthenticatorConfigModel config : getAuthenticatorConfigs()) {
            if (config.getAlias().equals(alias)) {
                return config;
            }
        }
        return null;
    }

    protected AuthenticationFlowModel entityToModel(AuthenticationFlow entity) {
        AuthenticationFlowModel model = new AuthenticationFlowModel();
        model.setId(entity.getId());
        model.setAlias(entity.getAlias());
        model.setProviderId(entity.getProviderId());
        model.setDescription(entity.getDescription());
        model.setBuiltIn(entity.isBuiltIn());
        model.setTopLevel(entity.isTopLevel());
        return model;
    }

    @Override
    public AuthenticationFlowModel getAuthenticationFlowById(String id) {
        Optional<AuthenticationFlow> optional = authenticationFlowRepository.findById(id);
        return optional.map(this::entityToModel).orElse(null);
    }

    @Override
    public void removeAuthenticationFlow(AuthenticationFlowModel model) {
        if (KeycloakModelUtils.isFlowUsed(this, model)) {
            throw new ModelException("Cannot remove authentication flow, it is currently in use");
        }

        authenticationFlowRepository.deleteById(model.getId());
    }

    @Override
    public void updateAuthenticationFlow(AuthenticationFlowModel model) {
        Optional<AuthenticationFlow> optional = authenticationFlowRepository.findById(model.getId());
        if (!optional.isPresent()) return;
        AuthenticationFlow entity = optional.get();
        entity.setAlias(model.getAlias());
        entity.setDescription(model.getDescription());
        entity.setProviderId(model.getProviderId());
        entity.setBuiltIn(model.isBuiltIn());
        entity.setTopLevel(model.isTopLevel());
    }

    @Override
    public AuthenticationFlowModel addAuthenticationFlow(AuthenticationFlowModel model) {
        AuthenticationFlow entity = new AuthenticationFlow();
        String id = (model.getId() == null) ? KeycloakModelUtils.generateId() : model.getId();
        entity.setId(id);
        entity.setAlias(model.getAlias());
        entity.setDescription(model.getDescription());
        entity.setProviderId(model.getProviderId());
        entity.setBuiltIn(model.isBuiltIn());
        entity.setTopLevel(model.isTopLevel());
        entity.setRealm(realm);
        realm.getAuthenticationFlows().add(entity);
        entity = authenticationFlowRepository.save(entity);
        model.setId(entity.getId());
        return model;
    }

    @Override
    public List<AuthenticationExecutionModel> getAuthenticationExecutions(String flowId) {
        AuthenticationFlow flow = authenticationFlowRepository.getOne(flowId);
        return flow.getExecutions().stream()
                .filter(e -> getId().equals(e.getRealm().getId()))
                .map(this::entityToModel)
                .sorted(AuthenticationExecutionModel.ExecutionComparator.SINGLETON)
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(), Collections::unmodifiableList));
    }

    public AuthenticationExecutionModel entityToModel(AuthenticationExecution entity) {
        AuthenticationExecutionModel model = new AuthenticationExecutionModel();
        model.setId(entity.getId());
        model.setRequirement(entity.getRequirement());
        model.setPriority(entity.getPriority());
        model.setAuthenticator(entity.getAuthenticator());
        model.setFlowId(entity.getFlowId());
        model.setParentFlow(entity.getParentFlow().getId());
        model.setAuthenticatorFlow(entity.isAutheticatorFlow());
        model.setAuthenticatorConfig(entity.getAuthenticatorConfig());
        return model;
    }

    @Override
    public AuthenticationExecutionModel getAuthenticationExecutionById(String id) {
        Optional<AuthenticationExecution> optional = authenticationExecutionRepository.findById(id);
        return optional.map(this::entityToModel).orElse(null);
    }

    public AuthenticationExecutionModel getAuthenticationExecutionByFlowId(String flowId) {
        List<AuthenticationExecution> results = authenticationExecutionRepository.authenticationFlowExecution(flowId);
        if (results.isEmpty()) {
            return null;
        }
        AuthenticationExecution authenticationFlowExecution = results.get(0);
        return entityToModel(authenticationFlowExecution);
    }

    @Override
    public AuthenticationExecutionModel addAuthenticatorExecution(AuthenticationExecutionModel model) {
        AuthenticationExecution entity = new AuthenticationExecution();
        String id = (model.getId() == null) ? KeycloakModelUtils.generateId() : model.getId();
        entity.setId(id);
        entity.setAuthenticator(model.getAuthenticator());
        entity.setPriority(model.getPriority());
        entity.setFlowId(model.getFlowId());
        entity.setRequirement(model.getRequirement());
        entity.setAuthenticatorConfig(model.getAuthenticatorConfig());
        AuthenticationFlow flow = authenticationFlowRepository.getOne(model.getParentFlow());
        entity.setParentFlow(flow);
        flow.getExecutions().add(entity);
        entity.setRealm(realm);
        entity.setAutheticatorFlow(model.isAuthenticatorFlow());
        entity = authenticationExecutionRepository.save(entity);
        model.setId(entity.getId());
        return model;
    }

    @Override
    public void updateAuthenticatorExecution(AuthenticationExecutionModel model) {
        Optional<AuthenticationExecution> optional = authenticationExecutionRepository.findById(model.getId());
        if (!optional.isPresent()) return;
        AuthenticationExecution entity = optional.get();
        entity.setAutheticatorFlow(model.isAuthenticatorFlow());
        entity.setAuthenticator(model.getAuthenticator());
        entity.setPriority(model.getPriority());
        entity.setRequirement(model.getRequirement());
        entity.setAuthenticatorConfig(model.getAuthenticatorConfig());
        entity.setFlowId(model.getFlowId());
        if (model.getParentFlow() != null) {
            AuthenticationFlow flow = authenticationFlowRepository.getOne(model.getParentFlow());
            entity.setParentFlow(flow);
        }
        authenticationExecutionRepository.save(entity);
    }

    @Override
    public void removeAuthenticatorExecution(AuthenticationExecutionModel model) {
        authenticationExecutionRepository.deleteById(model.getId());
    }

    @Override
    public AuthenticatorConfigModel addAuthenticatorConfig(AuthenticatorConfigModel model) {
        AuthenticatorConfig auth = new AuthenticatorConfig();
        String id = (model.getId() == null) ? KeycloakModelUtils.generateId() : model.getId();
        auth.setId(id);
        auth.setAlias(model.getAlias());
        auth.setRealm(realm);
        auth.setConfig(model.getConfig());
        realm.getAuthenticatorConfigs().add(auth);
        auth = authenticatorConfigRepository.save(auth);
        model.setId(auth.getId());
        realmRepository.save(realm);
        return model;
    }

    @Override
    public void removeAuthenticatorConfig(AuthenticatorConfigModel model) {
        authenticatorConfigRepository.deleteById(model.getId());
    }

    @Override
    public AuthenticatorConfigModel getAuthenticatorConfigById(String id) {
        Optional<AuthenticatorConfig> entity = authenticatorConfigRepository.findById(id);
        return entity.map(this::entityToModel).orElse(null);
    }

    public AuthenticatorConfigModel entityToModel(AuthenticatorConfig entity) {
        AuthenticatorConfigModel model = new AuthenticatorConfigModel();
        model.setId(entity.getId());
        model.setAlias(entity.getAlias());
        Map<String, String> config = new HashMap<>();
        if (entity.getConfig() != null) config.putAll(entity.getConfig());
        model.setConfig(config);
        return model;
    }

    @Override
    public void updateAuthenticatorConfig(AuthenticatorConfigModel model) {
        Optional<AuthenticatorConfig> optional = authenticatorConfigRepository.findById(model.getId());
        if (!optional.isPresent()) return;
        AuthenticatorConfig entity = optional.get();
        entity.setAlias(model.getAlias());
        if (entity.getConfig() == null) {
            entity.setConfig(model.getConfig());
        } else {
            entity.getConfig().clear();
            if (model.getConfig() != null) {
                entity.getConfig().putAll(model.getConfig());
            }
        }

        authenticatorConfigRepository.save(entity);
    }

    @Override
    public List<AuthenticatorConfigModel> getAuthenticatorConfigs() {
        Collection<AuthenticatorConfig> entities = realm.getAuthenticatorConfigs();
        if (entities.isEmpty()) return Collections.EMPTY_LIST;
        List<AuthenticatorConfigModel> authenticators = new LinkedList<>();
        for (AuthenticatorConfig entity : entities) {
            authenticators.add(entityToModel(entity));
        }
        return Collections.unmodifiableList(authenticators);
    }

    @Override
    public RequiredActionProviderModel addRequiredActionProvider(RequiredActionProviderModel model) {
        RequiredActionProvider auth = new RequiredActionProvider();
        String id = (model.getId() == null) ? KeycloakModelUtils.generateId() : model.getId();
        auth.setId(id);
        auth.setAlias(model.getAlias());
        auth.setName(model.getName());
        auth.setRealm(realm);
        auth.setProviderId(model.getProviderId());
        auth.setConfig(model.getConfig());
        auth.setEnabled(model.isEnabled());
        auth.setDefaultAction(model.isDefaultAction());
        auth.setPriority(model.getPriority());
        realm.getRequiredActionProviders().add(auth);
        requiredActionProviderRepository.save(auth);
        model.setId(auth.getId());
        return model;
    }

    @Override
    public void removeRequiredActionProvider(RequiredActionProviderModel model) {
        requiredActionProviderRepository.deleteById(model.getId());
    }

    @Override
    public RequiredActionProviderModel getRequiredActionProviderById(String id) {
        Optional<RequiredActionProvider> entity = requiredActionProviderRepository.findById(id);
        return entity.map(this::entityToModel).orElse(null);
    }

    public RequiredActionProviderModel entityToModel(RequiredActionProvider entity) {
        RequiredActionProviderModel model = new RequiredActionProviderModel();
        model.setId(entity.getId());
        model.setProviderId(entity.getProviderId());
        model.setAlias(entity.getAlias());
        model.setEnabled(entity.isEnabled());
        model.setDefaultAction(entity.isDefaultAction());
        model.setPriority(entity.getPriority());
        model.setName(entity.getName());
        Map<String, String> config = new HashMap<>();
        if (entity.getConfig() != null) config.putAll(entity.getConfig());
        model.setConfig(config);
        return model;
    }

    @Override
    public void updateRequiredActionProvider(RequiredActionProviderModel model) {
        Optional<RequiredActionProvider> optional = requiredActionProviderRepository.findById(model.getId());
        if (!optional.isPresent()) return;
        RequiredActionProvider entity = optional.get();
        entity.setAlias(model.getAlias());
        entity.setProviderId(model.getProviderId());
        entity.setEnabled(model.isEnabled());
        entity.setDefaultAction(model.isDefaultAction());
        entity.setPriority(model.getPriority());
        entity.setName(model.getName());
        if (entity.getConfig() == null) {
            entity.setConfig(model.getConfig());
        } else {
            entity.getConfig().clear();
            if (model.getConfig() != null) {
                entity.getConfig().putAll(model.getConfig());
            }
        }
    }

    @Override
    public List<RequiredActionProviderModel> getRequiredActionProviders() {
        Collection<RequiredActionProvider> entities = realm.getRequiredActionProviders();
        if (entities.isEmpty()) return Collections.EMPTY_LIST;
        List<RequiredActionProviderModel> actions = new LinkedList<>();
        for (RequiredActionProvider entity : entities) {
            actions.add(entityToModel(entity));
        }
        actions.sort(RequiredActionProviderModel.RequiredActionComparator.SINGLETON);
        return Collections.unmodifiableList(actions);
    }

    @Override
    public RequiredActionProviderModel getRequiredActionProviderByAlias(String alias) {
        for (RequiredActionProviderModel action : getRequiredActionProviders()) {
            if (action.getAlias().equals(alias)) return action;
        }
        return null;
    }

    @Override
    public GroupModel createGroup(String id, String name, GroupModel toParent) {
        return realmProvider.createGroup(this, id, name, toParent);
    }

    @Override
    public void moveGroup(GroupModel group, GroupModel toParent) {
        realmProvider.moveGroup(this, group, toParent);
    }

    @Override
    public GroupModel getGroupById(String id) {
        return realmProvider.getGroupById(id, this);
    }

    @Override
    public List<GroupModel> getGroups() {
        return realmProvider.getGroups(this);
    }

    @Override
    public Long getGroupsCount(Boolean onlyTopGroups) {
        return realmProvider.getGroupsCount(this, onlyTopGroups);
    }

    @Override
    public Long getGroupsCountByNameContaining(String search) {
        return realmProvider.getGroupsCountByNameContaining(this, search);
    }

    @Override
    public List<GroupModel> getTopLevelGroups() {
        return realmProvider.getTopLevelGroups(this);
    }

    @Override
    public List<GroupModel> getTopLevelGroups(Integer first, Integer max) {
        return realmProvider.getTopLevelGroups(this, first, max);
    }

    @Override
    public List<GroupModel> searchForGroupByName(String search, Integer first, Integer max) {
        return realmProvider.searchForGroupByName(this, search, first, max);
    }

    @Override
    public boolean removeGroup(GroupModel group) {
        return realmProvider.removeGroup(this, group);
    }

    @Override
    public List<ClientScopeModel> getClientScopes() {
        Collection<ClientScope> entities = realm.getClientScopes();
        if (entities == null || entities.isEmpty()) return Collections.EMPTY_LIST;
        List<ClientScopeModel> list = new LinkedList<>();
        for (ClientScope entity : entities) {
            list.add(realmProvider.getClientScopeById(entity.getId(), this));
        }
        return Collections.unmodifiableList(list);
    }

    @Override
    public ClientScopeModel addClientScope(String name) {
        return this.addClientScope(KeycloakModelUtils.generateId(), name);
    }

    @Override
    public ClientScopeModel addClientScope(String id, String name) {
        ClientScope entity = new ClientScope();
        entity.setId(id);
        name = KeycloakModelUtils.convertClientScopeName(name);
        entity.setName(name);
        entity.setRealm(realm);
        realm.getClientScopes().add(entity);
        clientScopeRepository.save(entity);
        return new ClientScopeAdapter(this, entity);
    }

    @Override
    public boolean removeClientScope(String id) {
        if (id == null) return false;
        ClientScopeModel clientScope = getClientScopeById(id);
        if (clientScope == null) return false;
        if (KeycloakModelUtils.isClientScopeUsed(this, clientScope)) {
            throw new ModelException("Cannot remove client scope, it is currently in use");
        }

        ClientScope clientScopeEntity = null;
        Iterator<ClientScope> it = realm.getClientScopes().iterator();
        while (it.hasNext()) {
            ClientScope ae = it.next();
            if (ae.getId().equals(id)) {
                clientScopeEntity = ae;
                it.remove();
                break;
            }
        }

        userProvider.preRemove(clientScope);

        clientScopeRoleMappingRepository.deleteClientScopeRoleMappingByClientScope(clientScopeEntity);
        clientScopeRepository.delete(clientScopeEntity);

        return true;
    }

    @Override
    public ClientScopeModel getClientScopeById(String id) {
        return realmProvider.getClientScopeById(id, this);
    }

    @Override
    public void addDefaultClientScope(ClientScopeModel clientScope, boolean defaultScope) {
        DefaultClientScopeRealmMapping entity = new DefaultClientScopeRealmMapping();
        entity.setClientScope(clientScopeAdapter.toClientScopeEntity(clientScope));
        entity.setRealm(getEntity());
        entity.setDefaultScope(defaultScope);
        defaultClientScopeRealmMappingRepository.save(entity);
    }

    @Override
    public void removeDefaultClientScope(ClientScopeModel clientScope) {
        defaultClientScopeRealmMappingRepository.deleteDefaultClientScopeRealmMapping(
                clientScopeAdapter.toClientScopeEntity(clientScope),
                getEntity()
        );
    }

    @Override
    public List<ClientScopeModel> getDefaultClientScopes(boolean defaultScope) {
        List<String> ids = defaultClientScopeRealmMappingRepository.defaultClientScopeRealmMappingIdsByRealm(getEntity(), defaultScope);
        List<ClientScopeModel> clientScopes = new LinkedList<>();
        for (String clientScopeId : ids) {
            ClientScopeModel clientScope = getClientScopeById(clientScopeId);
            if (clientScope == null) continue;
            clientScopes.add(clientScope);
        }
        return clientScopes;
    }

    @Autowired
    private ComponentUtil componentUtil;

    @Override
    public ComponentModel addComponentModel(ComponentModel model) {
        model = importComponentModel(model);
        componentUtil.notifyCreated(this, model);

        return model;
    }

    @Override
    public ComponentModel importComponentModel(ComponentModel model) {
        ComponentFactory componentFactory;
        try {
            componentFactory = componentUtil.getComponentFactory(model);
            if (componentFactory == null && System.getProperty(COMPONENT_PROVIDER_EXISTS_DISABLED) == null) {
                throw new IllegalArgumentException("Invalid component type");
            }
            componentFactory.validateConfiguration(this, model);
        } catch (Exception e) {
            if (System.getProperty(COMPONENT_PROVIDER_EXISTS_DISABLED) == null) {
                throw e;
            }
        }

        Component c = new Component();
        if (model.getId() == null) {
            c.setId(KeycloakModelUtils.generateId());
        } else {
            c.setId(model.getId());
        }
        c.setName(model.getName());
        c.setParentId(model.getParentId());
        if (model.getParentId() == null) {
            c.setParentId(this.getId());
            model.setParentId(this.getId());
        }
        c.setProviderType(model.getProviderType());
        c.setProviderId(model.getProviderId());
        c.setSubType(model.getSubType());
        c.setRealm(realm);
        componentRepository.save(c);

        realm.getComponents().add(c);
        setConfig(model, c);
        model.setId(c.getId());
        return model;
    }

    protected void setConfig(ComponentModel model, Component c) {
        c.getComponentConfigs().clear();
        for (String key : model.getConfig().keySet()) {
            List<String> vals = model.getConfig().get(key);
            if (vals == null) {
                continue;
            }
            for (String val : vals) {
                ComponentConfig config = new ComponentConfig();
                config.setId(KeycloakModelUtils.generateId());
                config.setName(key);
                config.setValue(val);
                config.setComponent(c);
                c.getComponentConfigs().add(config);
            }
        }
    }

    @Override
    public void updateComponent(ComponentModel component) {
        componentUtil.getComponentFactory(component).validateConfiguration(this, component);

        Optional<Component> optional = componentRepository.findById(component.getId());
        if (!optional.isPresent()) return;
        Component c = optional.get();
        ComponentModel old = entityToModel(c);
        c.setName(component.getName());
        c.setProviderId(component.getProviderId());
        c.setProviderType(component.getProviderType());
        c.setParentId(component.getParentId());
        c.setSubType(component.getSubType());
        setConfig(component, c);
        componentUtil.notifyUpdated(this, old, component);
    }

    @Override
    public void removeComponent(ComponentModel component) {
        Optional<Component> optional = componentRepository.findById(component.getId());
        if (!optional.isPresent()) return;
        userProvider.preRemove(this, component);
        componentUtil.notifyPreRemove(this, component);
        removeComponents(component.getId());
        getEntity().getComponents().remove(optional.get());
    }

    @Override
    public void removeComponents(String parentId) {
        Predicate<Component> sameParent = c -> Objects.equals(parentId, c.getParentId());
        getEntity().getComponents().stream()
                .filter(sameParent)
                .map(this::entityToModel)
                .forEach((ComponentModel c) -> {
                    userProvider.preRemove(this, c);
                    componentUtil.notifyPreRemove(this, c);
                });

        getEntity().getComponents().removeIf(sameParent);
    }

    @Override
    public List<ComponentModel> getComponents(String parentId, final String providerType) {
        if (parentId == null) parentId = getId();
        final String parent = parentId;

        return realm.getComponents().stream()
                .filter(c -> parent.equals(c.getParentId())
                        && providerType.equals(c.getProviderType()))
                .map(this::entityToModel)
                .collect(Collectors.toList());
    }

    @Override
    public List<ComponentModel> getComponents(final String parentId) {
        return realm.getComponents().stream()
                .filter(c -> parentId.equals(c.getParentId()))
                .map(this::entityToModel)
                .collect(Collectors.toList());
    }

    protected ComponentModel entityToModel(Component c) {
        ComponentModel model = new ComponentModel();
        model.setId(c.getId());
        model.setName(c.getName());
        model.setProviderType(c.getProviderType());
        model.setProviderId(c.getProviderId());
        model.setSubType(c.getSubType());
        model.setParentId(c.getParentId());
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        for (ComponentConfig configEntity : c.getComponentConfigs()) {
            config.add(configEntity.getName(), configEntity.getValue());
        }
        model.setConfig(config);
        return model;
    }

    @Override
    public List<ComponentModel> getComponents() {
        return realm.getComponents().stream().map(this::entityToModel).collect(Collectors.toList());
    }

    @Override
    public ComponentModel getComponent(String id) {
        Optional<Component> optional = componentRepository.findById(id);
        if (!optional.isPresent()) return null;
        return entityToModel(optional.get());
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}