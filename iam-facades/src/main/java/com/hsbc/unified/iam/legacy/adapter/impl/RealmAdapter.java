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

package com.hsbc.unified.iam.legacy.adapter.impl;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.facade.service.RealmFacade;
import com.hsbc.unified.iam.repository.ClientRepository;
import com.hsbc.unified.iam.service.RealmService;
import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientScopeAdapter;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.JpaModel;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.utils.ComponentUtil;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.TypedQuery;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RealmAdapter implements RealmModel, JpaModel<Realm> {
    /**
     * This just exists for testing purposes
     */
    public static final String COMPONENT_PROVIDER_EXISTS_DISABLED = "component.provider.exists.disabled";
    private static final String BROWSER_HEADER_PREFIX = "_browser_header.";
    protected Realm realm;
    protected EntityManager em;
    protected KeycloakSession session;
    private PasswordPolicy passwordPolicy;
    private OTPPolicy otpPolicy;

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private RealmService realmService;

    @Autowired
    private RealmFacade realmFacade;

    public RealmAdapter(KeycloakSession session, EntityManager em, Realm realm) {
        this.session = session;
        this.em = em;
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
        Role roleEntity = RoleAdapter.toRoleEntity(role, em);
        entities.add(roleEntity);
        em.flush();
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
        em.flush();
        for (String roleName : defaultRoles) {
            if (!already.contains(roleName)) {
                addDefaultRole(roleName);
            }
        }
        em.flush();
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
        em.flush();
    }

    @Override
    public List<GroupModel> getDefaultGroups() {
        Collection<Group> entities = realm.getDefaultGroups();
        if (entities == null || entities.isEmpty()) return Collections.EMPTY_LIST;
        List<GroupModel> defaultGroups = new LinkedList<>();
        for (Group entity : entities) {
            defaultGroups.add(session.realms().getGroupById(entity.getId(), this));
        }
        return Collections.unmodifiableList(defaultGroups);
    }

    @Override
    public void addDefaultGroup(GroupModel group) {
        Collection<Group> entities = realm.getDefaultGroups();
        for (Group entity : entities) {
            if (entity.getId().equals(group.getId())) return;
        }
        Group groupEntity = GroupAdapter.toEntity(group, em);
        realm.getDefaultGroups().add(groupEntity);
        em.flush();

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
            em.flush();
        }

    }

    @Override
    public List<ClientModel> getClients() {
        return session.realms().getClients(this);
    }

    @Override
    public List<ClientModel> getClients(Integer firstResult, Integer maxResults) {
        return session.realms().getClients(this, firstResult, maxResults);
    }

    @Override
    public List<ClientModel> getAlwaysDisplayInConsoleClients() {
        return session.realms().getAlwaysDisplayInConsoleClients(this);
    }

    @Override
    public ClientModel addClient(String name) {
        return session.realms().addClient(this, name);
    }

    @Override
    public ClientModel addClient(String id, String clientId) {
        return session.realms().addClient(this, id, clientId);
    }

    @Override
    public boolean removeClient(String id) {
        if (id == null) return false;
        ClientModel client = getClientById(id);
        if (client == null) return false;
        return session.realms().removeClient(id, this);
    }

    @Override
    public ClientModel getClientById(String id) {
        return session.realms().getClientById(id, this);
    }

    @Override
    public ClientModel getClientByClientId(String clientId) {
        return session.realms().getClientByClientId(clientId, this);
    }

    @Override
    public List<ClientModel> searchClientByClientId(String clientId, Integer firstResult, Integer maxResults) {
        return session.realms().searchClientsByClientId(clientId, firstResult, maxResults, this);
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
        Map<String, String> config = new HashMap<String, String>();
        config.putAll(realm.getSmtpConfig());
        return Collections.unmodifiableMap(config);
    }

    @Override
    public void setSmtpConfig(Map<String, String> smtpConfig) {
        realm.setSmtpConfig(smtpConfig);
        em.flush();
    }

    @Override
    public RoleModel getRole(String name) {
        return session.realms().getRealmRole(this, name);
    }

    @Override
    public RoleModel addRole(String name) {
        return session.realms().addRealmRole(this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return session.realms().addRealmRole(this, id, name);
    }

    @Override
    public boolean removeRole(RoleModel role) {
        return session.realms().removeRole(this, role);
    }

    @Override
    public Set<RoleModel> getRoles() {
        return session.realms().getRealmRoles(this);
    }

    @Override
    public Set<RoleModel> getRoles(Integer first, Integer max) {
        return session.realms().getRealmRoles(this, first, max);
    }

    @Override
    public Set<RoleModel> searchForRoles(String search, Integer first, Integer max) {
        return session.realms().searchForRoles(this, search, first, max);
    }

    @Override
    public RoleModel getRoleById(String id) {
        return session.realms().getRoleById(id, this);
    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        if (passwordPolicy == null) {
            passwordPolicy = PasswordPolicy.parse(session, realm.getPasswordPolicy());
        }
        return passwordPolicy;
    }

    @Override
    public void setPasswordPolicy(PasswordPolicy policy) {
        this.passwordPolicy = policy;
        realm.setPasswordPolicy(policy.toString());
        em.flush();
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
        em.flush();
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
        em.flush();
    }

    @Override
    public String getAccountTheme() {
        return realm.getAccountTheme();
    }

    @Override
    public void setAccountTheme(String name) {
        realm.setAccountTheme(name);
        em.flush();
    }

    @Override
    public String getAdminTheme() {
        return realm.getAdminTheme();
    }

    @Override
    public void setAdminTheme(String name) {
        realm.setAdminTheme(name);
        em.flush();
    }

    @Override
    public String getEmailTheme() {
        return realm.getEmailTheme();
    }

    @Override
    public void setEmailTheme(String name) {
        realm.setEmailTheme(name);
        em.flush();
    }

    @Override
    public boolean isEventsEnabled() {
        return realm.isEventsEnabled();
    }

    @Override
    public void setEventsEnabled(boolean enabled) {
        realm.setEventsEnabled(enabled);
        em.flush();
    }

    @Override
    public long getEventsExpiration() {
        return realm.getEventsExpiration();
    }

    @Override
    public void setEventsExpiration(long expiration) {
        realm.setEventsExpiration(expiration);
        em.flush();
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
        em.flush();
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
        em.flush();
    }

    @Override
    public boolean isAdminEventsEnabled() {
        return realm.isAdminEventsEnabled();
    }

    @Override
    public void setAdminEventsEnabled(boolean enabled) {
        realm.setAdminEventsEnabled(enabled);
        em.flush();
    }

    @Override
    public boolean isAdminEventsDetailsEnabled() {
        return realm.isAdminEventsDetailsEnabled();
    }

    @Override
    public void setAdminEventsDetailsEnabled(boolean enabled) {
        realm.setAdminEventsDetailsEnabled(enabled);
        em.flush();
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
            masterRealm = session.realms().getRealm(masterAdminClientRealmId);
        }
        return session.realms().getClientById(masterAdminClient.getId(), masterRealm);
    }

    @Override
    public void setMasterAdminClient(ClientModel client) {
        Client appEntity = client != null ? em.getReference(Client.class, client.getId()) : null;
        realm.setMasterAdminClient(appEntity);
        em.flush();
    }

    @Override
    public List<IdentityProviderModel> getIdentityProviders() {
        List<IdentityProvider> entities = realm.getIdentityProviders();
        if (entities.isEmpty()) return Collections.EMPTY_LIST;
        List<IdentityProviderModel> identityProviders = new ArrayList<IdentityProviderModel>();

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
        Map<String, String> copy = new HashMap<>();
        copy.putAll(config);
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

        em.persist(entity);
        em.flush();
    }

    @Override
    public void removeIdentityProviderByAlias(String alias) {
        for (IdentityProvider entity : realm.getIdentityProviders()) {
            if (entity.getAlias().equals(alias)) {

                IdentityProviderModel model = entityToModel(entity);
                em.remove(entity);
                em.flush();

                session.getSessionFactory().publish(new RealmModel.IdentityProviderRemovedEvent() {

                    @Override
                    public RealmModel getRealm() {
                        return RealmAdapter.this;
                    }

                    @Override
                    public IdentityProviderModel getRemovedIdentityProvider() {
                        return model;
                    }

                    @Override
                    public KeycloakSession getSession() {
                        return session;
                    }
                });

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

        em.flush();

        session.getSessionFactory().publish(new RealmModel.IdentityProviderUpdatedEvent() {

            @Override
            public RealmModel getRealm() {
                return RealmAdapter.this;
            }

            @Override
            public IdentityProviderModel getUpdatedIdentityProvider() {
                return identityProvider;
            }

            @Override
            public KeycloakSession getSession() {
                return session;
            }
        });
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
        em.flush();
    }

    @Override
    public Set<String> getSupportedLocales() {
        Set<String> supportedLocales = realm.getSupportedLocales();
        if (supportedLocales == null || supportedLocales.isEmpty()) return Collections.EMPTY_SET;
        Set<String> copy = new HashSet<>();
        copy.addAll(supportedLocales);
        return Collections.unmodifiableSet(copy);
    }

    @Override
    public void setSupportedLocales(Set<String> locales) {
        realm.setSupportedLocales(locales);
        em.flush();
    }

    @Override
    public String getDefaultLocale() {
        return realm.getDefaultLocale();
    }

    @Override
    public void setDefaultLocale(String locale) {
        realm.setDefaultLocale(locale);
        em.flush();
    }

    @Override
    public Set<IdentityProviderMapperModel> getIdentityProviderMappers() {
        Collection<IdentityProviderMapper> entities = this.realm.getIdentityProviderMappers();
        if (entities.isEmpty()) return Collections.EMPTY_SET;
        Set<IdentityProviderMapperModel> mappings = new HashSet<IdentityProviderMapperModel>();
        for (IdentityProviderMapper entity : entities) {
            IdentityProviderMapperModel mapping = entityToModel(entity);
            mappings.add(mapping);
        }
        return Collections.unmodifiableSet(mappings);
    }

    @Override
    public Set<IdentityProviderMapperModel> getIdentityProviderMappersByAlias(String brokerAlias) {
        Set<IdentityProviderMapperModel> mappings = new HashSet<IdentityProviderMapperModel>();
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

        em.persist(entity);
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
            em.remove(toDelete);
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
        em.flush();

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
        AuthenticationFlow entity = em.find(AuthenticationFlow.class, id);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    @Override
    public void removeAuthenticationFlow(AuthenticationFlowModel model) {
        if (KeycloakModelUtils.isFlowUsed(this, model)) {
            throw new ModelException("Cannot remove authentication flow, it is currently in use");
        }
        AuthenticationFlow entity = em.find(AuthenticationFlow.class, model.getId(), LockModeType.PESSIMISTIC_WRITE);

        em.remove(entity);
        em.flush();
    }

    @Override
    public void updateAuthenticationFlow(AuthenticationFlowModel model) {
        AuthenticationFlow entity = em.find(AuthenticationFlow.class, model.getId());
        if (entity == null) return;
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
        em.persist(entity);
        model.setId(entity.getId());
        return model;
    }

    @Override
    public List<AuthenticationExecutionModel> getAuthenticationExecutions(String flowId) {
        AuthenticationFlow flow = em.getReference(AuthenticationFlow.class, flowId);

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
        AuthenticationExecution entity = em.find(AuthenticationExecution.class, id);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    public AuthenticationExecutionModel getAuthenticationExecutionByFlowId(String flowId) {
        TypedQuery<AuthenticationExecution> query = em.createNamedQuery("authenticationFlowExecution", AuthenticationExecution.class)
                .setParameter("flowId", flowId);
        if (query.getResultList().isEmpty()) {
            return null;
        }
        AuthenticationExecution authenticationFlowExecution = query.getResultList().get(0);
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
        AuthenticationFlow flow = em.find(AuthenticationFlow.class, model.getParentFlow());
        entity.setParentFlow(flow);
        flow.getExecutions().add(entity);
        entity.setRealm(realm);
        entity.setAutheticatorFlow(model.isAuthenticatorFlow());
        em.persist(entity);
        model.setId(entity.getId());
        return model;

    }

    @Override
    public void updateAuthenticatorExecution(AuthenticationExecutionModel model) {
        AuthenticationExecution entity = em.find(AuthenticationExecution.class, model.getId());
        if (entity == null) return;
        entity.setAutheticatorFlow(model.isAuthenticatorFlow());
        entity.setAuthenticator(model.getAuthenticator());
        entity.setPriority(model.getPriority());
        entity.setRequirement(model.getRequirement());
        entity.setAuthenticatorConfig(model.getAuthenticatorConfig());
        entity.setFlowId(model.getFlowId());
        if (model.getParentFlow() != null) {
            AuthenticationFlow flow = em.find(AuthenticationFlow.class, model.getParentFlow());
            entity.setParentFlow(flow);
        }
        em.flush();
    }

    @Override
    public void removeAuthenticatorExecution(AuthenticationExecutionModel model) {
        AuthenticationExecution entity = em.find(AuthenticationExecution.class, model.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (entity == null) return;
        em.remove(entity);
        em.flush();

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
        em.persist(auth);
        model.setId(auth.getId());
        return model;
    }

    @Override
    public void removeAuthenticatorConfig(AuthenticatorConfigModel model) {
        AuthenticatorConfig entity = em.find(AuthenticatorConfig.class, model.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (entity == null) return;
        em.remove(entity);
        em.flush();

    }

    @Override
    public AuthenticatorConfigModel getAuthenticatorConfigById(String id) {
        AuthenticatorConfig entity = em.find(AuthenticatorConfig.class, id);
        if (entity == null) return null;
        return entityToModel(entity);
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
        AuthenticatorConfig entity = em.find(AuthenticatorConfig.class, model.getId());
        if (entity == null) return;
        entity.setAlias(model.getAlias());
        if (entity.getConfig() == null) {
            entity.setConfig(model.getConfig());
        } else {
            entity.getConfig().clear();
            if (model.getConfig() != null) {
                entity.getConfig().putAll(model.getConfig());
            }
        }
        em.flush();

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
        em.persist(auth);
        em.flush();
        model.setId(auth.getId());
        return model;
    }

    @Override
    public void removeRequiredActionProvider(RequiredActionProviderModel model) {
        RequiredActionProvider entity = em.find(RequiredActionProvider.class, model.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (entity == null) return;
        em.remove(entity);
        em.flush();

    }

    @Override
    public RequiredActionProviderModel getRequiredActionProviderById(String id) {
        RequiredActionProvider entity = em.find(RequiredActionProvider.class, id);
        if (entity == null) return null;
        return entityToModel(entity);
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
        RequiredActionProvider entity = em.find(RequiredActionProvider.class, model.getId());
        if (entity == null) return;
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
        em.flush();

    }

    @Override
    public List<RequiredActionProviderModel> getRequiredActionProviders() {
        Collection<RequiredActionProvider> entities = realm.getRequiredActionProviders();
        if (entities.isEmpty()) return Collections.EMPTY_LIST;
        List<RequiredActionProviderModel> actions = new LinkedList<>();
        for (RequiredActionProvider entity : entities) {
            actions.add(entityToModel(entity));
        }
        Collections.sort(actions, RequiredActionProviderModel.RequiredActionComparator.SINGLETON);
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
        return session.realms().createGroup(this, id, name, toParent);
    }

    @Override
    public void moveGroup(GroupModel group, GroupModel toParent) {
        session.realms().moveGroup(this, group, toParent);
    }

    @Override
    public GroupModel getGroupById(String id) {
        return session.realms().getGroupById(id, this);
    }

    @Override
    public List<GroupModel> getGroups() {
        return session.realms().getGroups(this);
    }

    @Override
    public Long getGroupsCount(Boolean onlyTopGroups) {
        return session.realms().getGroupsCount(this, onlyTopGroups);
    }

    @Override
    public Long getGroupsCountByNameContaining(String search) {
        return session.realms().getGroupsCountByNameContaining(this, search);
    }

    @Override
    public List<GroupModel> getTopLevelGroups() {
        return session.realms().getTopLevelGroups(this);
    }

    @Override
    public List<GroupModel> getTopLevelGroups(Integer first, Integer max) {
        return session.realms().getTopLevelGroups(this, first, max);
    }

    @Override
    public List<GroupModel> searchForGroupByName(String search, Integer first, Integer max) {
        return session.realms().searchForGroupByName(this, search, first, max);
    }

    @Override
    public boolean removeGroup(GroupModel group) {
        return session.realms().removeGroup(this, group);
    }

    @Override
    public List<ClientScopeModel> getClientScopes() {
        Collection<ClientScope> entities = realm.getClientScopes();
        if (entities == null || entities.isEmpty()) return Collections.EMPTY_LIST;
        List<ClientScopeModel> list = new LinkedList<>();
        for (ClientScope entity : entities) {
            list.add(session.realms().getClientScopeById(entity.getId(), this));
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
        em.persist(entity);
        em.flush();
        final ClientScopeModel resource = new ClientScopeAdapter(this, em, session, entity);
        em.flush();
        return resource;
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
        if (clientScope == null) {
            return false;
        }

        session.users().preRemove(clientScope);

        em.createNamedQuery("deleteClientScopeRoleMappingByClientScope").setParameter("clientScope", clientScopeEntity).executeUpdate();
        em.flush();
        em.remove(clientScopeEntity);
        em.flush();


        return true;
    }

    @Override
    public ClientScopeModel getClientScopeById(String id) {
        return session.realms().getClientScopeById(id, this);
    }

    @Override
    public void addDefaultClientScope(ClientScopeModel clientScope, boolean defaultScope) {
        DefaultClientScopeRealmMapping entity = new DefaultClientScopeRealmMapping();
        entity.setClientScope(ClientScopeAdapter.toClientScopeEntity(clientScope, em));
        entity.setRealm(getEntity());
        entity.setDefaultScope(defaultScope);
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public void removeDefaultClientScope(ClientScopeModel clientScope) {
        int numRemoved = em.createNamedQuery("deleteDefaultClientScopeRealmMapping")
                .setParameter("clientScope", ClientScopeAdapter.toClientScopeEntity(clientScope, em))
                .setParameter("realm", getEntity())
                .executeUpdate();
        em.flush();
    }

    @Override
    public List<ClientScopeModel> getDefaultClientScopes(boolean defaultScope) {
        TypedQuery<String> query = em.createNamedQuery("defaultClientScopeRealmMappingIdsByRealm", String.class);
        query.setParameter("realm", getEntity());
        query.setParameter("defaultScope", defaultScope);
        List<String> ids = query.getResultList();

        List<ClientScopeModel> clientScopes = new LinkedList<>();
        for (String clientScopeId : ids) {
            ClientScopeModel clientScope = getClientScopeById(clientScopeId);
            if (clientScope == null) continue;
            clientScopes.add(clientScope);
        }
        return clientScopes;
    }

    @Override
    public ComponentModel addComponentModel(ComponentModel model) {
        model = importComponentModel(model);
        ComponentUtil.notifyCreated(session, this, model);

        return model;
    }

    @Override
    public ComponentModel importComponentModel(ComponentModel model) {
        ComponentFactory componentFactory = null;
        try {
            componentFactory = ComponentUtil.getComponentFactory(session, model);
            if (componentFactory == null && System.getProperty(COMPONENT_PROVIDER_EXISTS_DISABLED) == null) {
                throw new IllegalArgumentException("Invalid component type");
            }
            componentFactory.validateConfiguration(session, this, model);
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
        em.persist(c);
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
        ComponentUtil.getComponentFactory(session, component).validateConfiguration(session, this, component);

        Component c = em.find(Component.class, component.getId());
        if (c == null) return;
        ComponentModel old = entityToModel(c);
        c.setName(component.getName());
        c.setProviderId(component.getProviderId());
        c.setProviderType(component.getProviderType());
        c.setParentId(component.getParentId());
        c.setSubType(component.getSubType());
        setConfig(component, c);
        ComponentUtil.notifyUpdated(session, this, old, component);


    }

    @Override
    public void removeComponent(ComponentModel component) {
        Component c = em.find(Component.class, component.getId());
        if (c == null) return;
        session.users().preRemove(this, component);
        ComponentUtil.notifyPreRemove(session, this, component);
        removeComponents(component.getId());
        getEntity().getComponents().remove(c);
    }

    @Override
    public void removeComponents(String parentId) {
        Predicate<Component> sameParent = c -> Objects.equals(parentId, c.getParentId());

        getEntity().getComponents().stream()
                .filter(sameParent)
                .map(this::entityToModel)
                .forEach((ComponentModel c) -> {
                    session.users().preRemove(this, c);
                    ComponentUtil.notifyPreRemove(session, this, c);
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
        Component c = em.find(Component.class, id);
        if (c == null) return null;
        return entityToModel(c);
    }
}