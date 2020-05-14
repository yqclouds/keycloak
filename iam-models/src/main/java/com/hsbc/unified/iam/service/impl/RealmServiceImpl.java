package com.hsbc.unified.iam.service.impl;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.entity.Realm;
import com.hsbc.unified.iam.entity.RealmAttribute;
import com.hsbc.unified.iam.entity.SslRequired;
import com.hsbc.unified.iam.repository.RealmAttributeRepository;
import com.hsbc.unified.iam.repository.RealmRepository;
import com.hsbc.unified.iam.service.RealmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static java.util.Objects.nonNull;

@Service
@Transactional(readOnly = true)
public class RealmServiceImpl implements RealmService {
    @Autowired
    private RealmRepository realmRepository;
    @Autowired
    private RealmAttributeRepository realmAttributeRepository;

    @Override
    @Transactional
    public Realm createRealm(String id, String name) {
        Realm entity = new Realm();
        entity.setId(id);
        entity.setName(name);

        return realmRepository.saveAndFlush(entity);
    }

    @Override
    public Realm getRealm(String id) {
        return realmRepository.getOne(id);
    }

    @Override
    public boolean removeRealm(Realm realm) {
        realmRepository.delete(realm);
        return true;
    }

    @Override
    public void removeDefaultGroups(Realm entity) {
        entity.getDefaultGroups().clear();
        realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getId(Realm entity) {
        return entity.getId();
    }

    @Override
    public String getName(Realm entity) {
        return entity.getName();
    }

    @Override
    @Transactional
    public void setName(Realm entity, String name) {
        entity.setName(name);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getDisplayName(Realm entity) {
        return getAttribute(entity, RealmAttribute.DISPLAY_NAME);
    }

    @Override
    @Transactional
    public void setDisplayName(Realm entity, String displayName) {
        setAttribute(entity, RealmAttribute.DISPLAY_NAME, displayName);
    }

    @Override
    public String getDisplayNameHtml(Realm entity) {
        return getAttribute(entity, RealmAttribute.DISPLAY_NAME_HTML);
    }

    @Override
    @Transactional
    public void setDisplayNameHtml(Realm entity, String displayNameHtml) {
        setAttribute(entity, RealmAttribute.DISPLAY_NAME_HTML, displayNameHtml);
    }

    @Override
    public boolean isEnabled(Realm entity) {
        return entity.isEnabled();
    }

    @Override
    @Transactional
    public void setEnabled(Realm entity, boolean enabled) {
        entity.setEnabled(enabled);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public SslRequired getSslRequired(Realm entity) {
        return entity.getSslRequired() != null ? SslRequired.valueOf(entity.getSslRequired()) : null;
    }

    @Override
    @Transactional
    public void setSslRequired(Realm entity, SslRequired sslRequired) {
        entity.setSslRequired(sslRequired.name());
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isUserManagedAccessAllowed(Realm entity) {
        return entity.isAllowUserManagedAccess();
    }

    @Override
    @Transactional
    public void setUserManagedAccessAllowed(Realm entity, boolean userManagedAccessAllowed) {
        entity.setAllowUserManagedAccess(userManagedAccessAllowed);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isRegistrationAllowed(Realm entity) {
        return entity.isRegistrationAllowed();
    }

    @Override
    public void setRegistrationAllowed(Realm entity, boolean registrationAllowed) {
        entity.setRegistrationAllowed(registrationAllowed);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isRegistrationEmailAsUsername(Realm entity) {
        return entity.isRegistrationEmailAsUsername();
    }

    @Override
    public void setRegistrationEmailAsUsername(Realm entity, boolean registrationEmailAsUsername) {
        entity.setRegistrationEmailAsUsername(registrationEmailAsUsername);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isRememberMe(Realm entity) {
        return entity.isRememberMe();
    }

    @Override
    public void setRememberMe(Realm entity, boolean rememberMe) {
        entity.setRememberMe(rememberMe);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getDefaultSignatureAlgorithm(Realm entity) {
        return getAttribute(entity, "defaultSignatureAlgorithm");
    }

    @Override
    public void setDefaultSignatureAlgorithm(Realm entity, String defaultSignatureAlgorithm) {
        setAttribute(entity, "defaultSignatureAlgorithm", defaultSignatureAlgorithm);
    }

    @Override
    public boolean isBruteForceProtected(Realm entity) {
        return getAttribute(entity, "bruteForceProtected", false);
    }

    @Override
    public void setBruteForceProtected(Realm entity, boolean value) {
        setAttribute(entity, "bruteForceProtected", value);
    }

    @Override
    public boolean isPermanentLockout(Realm entity) {
        return getAttribute(entity, "permanentLockout", false);
    }

    @Override
    public void setPermanentLockout(Realm entity, boolean val) {
        setAttribute(entity, "permanentLockout", val);
    }

    @Override
    public int getMaxFailureWaitSeconds(Realm entity) {
        return getAttribute(entity, "maxFailureWaitSeconds", 0);
    }

    @Override
    public void setMaxFailureWaitSeconds(Realm entity, int val) {
        setAttribute(entity, "maxFailureWaitSeconds", val);
    }

    @Override
    public int getWaitIncrementSeconds(Realm entity) {
        return getAttribute(entity, "waitIncrementSeconds", 0);
    }

    @Override
    public void setWaitIncrementSeconds(Realm entity, int val) {
        setAttribute(entity, "waitIncrementSeconds", val);
    }

    @Override
    public int getMinimumQuickLoginWaitSeconds(Realm entity) {
        return getAttribute(entity, "minimumQuickLoginWaitSeconds", 0);
    }

    @Override
    public void setMinimumQuickLoginWaitSeconds(Realm entity, int val) {
        setAttribute(entity, "minimumQuickLoginWaitSeconds", val);
    }

    @Override
    public long getQuickLoginCheckMilliSeconds(Realm entity) {
        return getAttribute(entity, "quickLoginCheckMilliSeconds", 0L);
    }

    @Override
    public void setQuickLoginCheckMilliSeconds(Realm entity, long val) {
        setAttribute(entity, "quickLoginCheckMilliSeconds", val);
    }

    @Override
    public int getMaxDeltaTimeSeconds(Realm entity) {
        return getAttribute(entity, "maxDeltaTimeSeconds", 0);
    }

    @Override
    public void setMaxDeltaTimeSeconds(Realm entity, int val) {
        setAttribute(entity, "maxDeltaTimeSeconds", val);
    }

    @Override
    public int getFailureFactor(Realm entity) {
        return getAttribute(entity, "failureFactor", 0);
    }

    @Override
    public void setFailureFactor(Realm entity, int failureFactor) {
        setAttribute(entity, "failureFactor", failureFactor);
    }

    @Override
    public boolean isVerifyEmail(Realm entity) {
        return entity.isVerifyEmail();
    }

    @Override
    public void setVerifyEmail(Realm entity, boolean verifyEmail) {
        entity.setVerifyEmail(verifyEmail);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isLoginWithEmailAllowed(Realm entity) {
        return entity.isLoginWithEmailAllowed();
    }

    @Override
    public void setLoginWithEmailAllowed(Realm entity, boolean loginWithEmailAllowed) {
        entity.setLoginWithEmailAllowed(loginWithEmailAllowed);
        if (loginWithEmailAllowed) {
            entity.setDuplicateEmailsAllowed(false);
        }
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isDuplicateEmailsAllowed(Realm entity) {
        return entity.isDuplicateEmailsAllowed();
    }

    @Override
    public void setDuplicateEmailsAllowed(Realm entity, boolean duplicateEmailsAllowed) {
        entity.setDuplicateEmailsAllowed(duplicateEmailsAllowed);
        if (duplicateEmailsAllowed) {
            entity.setLoginWithEmailAllowed(false);
            entity.setRegistrationEmailAsUsername(false);
        }

        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isResetPasswordAllowed(Realm entity) {
        return entity.isResetPasswordAllowed();
    }

    @Override
    public void setResetPasswordAllowed(Realm entity, boolean resetPasswordAllowed) {
        entity.setResetPasswordAllowed(resetPasswordAllowed);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isRevokeRefreshToken(Realm entity) {
        return entity.isRevokeRefreshToken();
    }

    @Override
    public void setRevokeRefreshToken(Realm entity, boolean revokeRefreshToken) {
        entity.setRevokeRefreshToken(revokeRefreshToken);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getRefreshTokenMaxReuse(Realm entity) {
        return entity.getRefreshTokenMaxReuse();
    }

    @Override
    public void setRefreshTokenMaxReuse(Realm entity, int revokeRefreshTokenCount) {
        entity.setRefreshTokenMaxReuse(revokeRefreshTokenCount);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getSsoSessionIdleTimeout(Realm entity) {
        return entity.getSsoSessionIdleTimeout();
    }

    @Override
    public void setSsoSessionIdleTimeout(Realm entity, int seconds) {
        entity.setSsoSessionIdleTimeout(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getSsoSessionMaxLifespan(Realm entity) {
        return entity.getSsoSessionMaxLifespan();
    }

    @Override
    public void setSsoSessionMaxLifespan(Realm entity, int seconds) {
        entity.setSsoSessionMaxLifespan(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getSsoSessionIdleTimeoutRememberMe(Realm entity) {
        return entity.getSsoSessionIdleTimeoutRememberMe();
    }

    @Override
    public void setSsoSessionIdleTimeoutRememberMe(Realm entity, int seconds) {
        entity.setSsoSessionIdleTimeoutRememberMe(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getSsoSessionMaxLifespanRememberMe(Realm entity) {
        return entity.getSsoSessionMaxLifespanRememberMe();
    }

    @Override
    public void setSsoSessionMaxLifespanRememberMe(Realm entity, int seconds) {
        entity.setSsoSessionMaxLifespanRememberMe(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getOfflineSessionIdleTimeout(Realm entity) {
        return entity.getOfflineSessionIdleTimeout();
    }

    @Override
    public void setOfflineSessionIdleTimeout(Realm entity, int seconds) {
        entity.setOfflineSessionIdleTimeout(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getAccessTokenLifespan(Realm entity) {
        return entity.getAccessTokenLifespan();
    }

    @Override
    public void setAccessTokenLifespan(Realm entity, int tokenLifespan) {
        entity.setAccessTokenLifespan(tokenLifespan);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public boolean isOfflineSessionMaxLifespanEnabled(Realm entity) {
        return getAttribute(entity, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN_ENABLED, false);
    }

    @Override
    public void setOfflineSessionMaxLifespanEnabled(Realm entity, boolean offlineSessionMaxLifespanEnabled) {
        setAttribute(entity, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN_ENABLED, offlineSessionMaxLifespanEnabled);
    }

    @Override
    public int getOfflineSessionMaxLifespan(Realm entity) {
        return getAttribute(entity, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN, Constants.DEFAULT_OFFLINE_SESSION_MAX_LIFESPAN);
    }

    @Override
    public void setOfflineSessionMaxLifespan(Realm entity, int seconds) {
        setAttribute(entity, RealmAttribute.OFFLINE_SESSION_MAX_LIFESPAN, seconds);
    }

    @Override
    public int getAccessTokenLifespanForImplicitFlow(Realm entity) {
        return entity.getAccessTokenLifespanForImplicitFlow();
    }

    @Override
    public void setAccessTokenLifespanForImplicitFlow(Realm entity, int seconds) {
        entity.setAccessTokenLifespanForImplicitFlow(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getAccessCodeLifespan(Realm entity) {
        return entity.getAccessCodeLifespan();
    }

    @Override
    public void setAccessCodeLifespan(Realm entity, int accessCodeLifespan) {
        entity.setAccessCodeLifespan(accessCodeLifespan);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getAccessCodeLifespanUserAction(Realm entity) {
        return entity.getAccessCodeLifespanUserAction();
    }

    @Override
    public void setAccessCodeLifespanUserAction(Realm entity, int seconds) {
        entity.setAccessCodeLifespanUserAction(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public Map<String, Integer> getUserActionTokenLifespans(Realm entity) {
        Map<String, Integer> userActionTokens = new HashMap<>();
        getAttributes(entity).entrySet().stream()
                .filter(Objects::nonNull)
                .filter(entry -> nonNull(entry.getValue()))
                .filter(entry -> entry.getKey().startsWith(RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + "."))
                .forEach(entry -> userActionTokens.put(entry.getKey().substring(RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN.length() + 1), Integer.valueOf(entry.getValue())));

        return Collections.unmodifiableMap(userActionTokens);
    }

    @Override
    public int getAccessCodeLifespanLogin(Realm entity) {
        return entity.getAccessCodeLifespanLogin();
    }

    @Override
    public void setAccessCodeLifespanLogin(Realm entity, int seconds) {
        entity.setAccessCodeLifespanLogin(seconds);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getActionTokenGeneratedByAdminLifespan(Realm entity) {
        return getAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN, 12 * 60 * 60);
    }

    @Override
    public void setActionTokenGeneratedByAdminLifespan(Realm entity, int seconds) {
        setAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN, seconds);
    }

    @Override
    public int getActionTokenGeneratedByUserLifespan(Realm entity) {
        return getAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN, getAccessCodeLifespanUserAction(entity));
    }

    @Override
    public void setActionTokenGeneratedByUserLifespan(Realm entity, int seconds) {
        setAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN, seconds);
    }

    @Override
    public int getActionTokenGeneratedByUserLifespan(Realm entity, String actionTokenType) {
        return getAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN, getAccessCodeLifespanUserAction(entity));
    }

    @Override
    public void setActionTokenGeneratedByUserLifespan(Realm entity, String actionTokenType, Integer seconds) {
        if (seconds != null) {
            setAttribute(entity, RealmAttribute.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + "." + actionTokenType, seconds);
            this.realmRepository.saveAndFlush(entity);
        }
    }

    @Override
    public boolean isEditUsernameAllowed(Realm entity) {
        return entity.isEditUsernameAllowed();
    }

    @Override
    public void setEditUsernameAllowed(Realm entity, boolean editUsernameAllowed) {
        entity.setEditUsernameAllowed(editUsernameAllowed);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public int getNotBefore(Realm entity) {
        return entity.getNotBefore();
    }

    @Override
    public void setNotBefore(Realm entity, int notBefore) {
        entity.setNotBefore(notBefore);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, String value) {
        for (RealmAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                attr.setValue(value);
                return;
            }
        }

        RealmAttribute attr = new RealmAttribute();
        attr.setName(name);
        attr.setValue(value);
        attr.setRealm(entity);
        this.realmAttributeRepository.saveAndFlush(attr);

        entity.getAttributes().add(attr);

        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Boolean value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Integer value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Long value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void removeAttribute(Realm entity, String name) {
        Iterator<RealmAttribute> it = entity.getAttributes().iterator();
        while (it.hasNext()) {
            RealmAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                this.realmAttributeRepository.delete(attr);
            }
        }

        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getAttribute(Realm entity, String name) {
        for (RealmAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                return attr.getValue();
            }
        }

        return null;
    }

    @Override
    public Integer getAttribute(Realm entity, String name, Integer defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Integer.parseInt(v) : defaultValue;
    }

    @Override
    public Long getAttribute(Realm entity, String name, Long defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Long.parseLong(v) : defaultValue;
    }

    @Override
    public Boolean getAttribute(Realm entity, String name, Boolean defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Boolean.parseBoolean(v) : defaultValue;
    }

    @Override
    public Map<String, String> getAttributes(Realm entity) {
        // should always return a copy
        Map<String, String> results = new HashMap<>();
        for (RealmAttribute attr : entity.getAttributes()) {
            results.put(attr.getName(), attr.getValue());
        }
        return results;
    }

    @Override
    public List<String> getRealmsWithProviderType(Class<?> providerType) {
        return this.realmRepository.getRealmIdsWithProviderType(providerType.getName());
    }

    @Override
    public List<String> getAllRealmIds() {
        return this.realmRepository.getAllRealmIds();
    }

    @Override
    public List<String> getRealmIdByName(String name) {
        return this.realmRepository.getRealmIdByName(name);
    }
}
