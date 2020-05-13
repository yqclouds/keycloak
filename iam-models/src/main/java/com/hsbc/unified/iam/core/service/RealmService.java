package com.hsbc.unified.iam.core.service;

import com.hsbc.unified.iam.core.entity.Realm;
import com.hsbc.unified.iam.core.entity.SslRequired;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Map;

public interface RealmService {
    Realm createRealm(String id, String name);

    Realm getRealm(String id);

    boolean removeRealm(Realm realm);

    void removeDefaultGroups(Realm entity);

    String getId(Realm entity);

    String getName(Realm entity);

    void setName(Realm entity, String name);

    String getDisplayName(Realm entity);

    void setDisplayName(Realm entity, String displayName);

    String getDisplayNameHtml(Realm entity);

    void setDisplayNameHtml(Realm entity, String displayNameHtml);

    boolean isEnabled(Realm entity);

    void setEnabled(Realm entity, boolean enabled);

    SslRequired getSslRequired(Realm entity);

    void setSslRequired(Realm entity, SslRequired sslRequired);

    boolean isUserManagedAccessAllowed(Realm entity);

    void setUserManagedAccessAllowed(Realm entity, boolean userManagedAccessAllowed);

    boolean isRegistrationAllowed(Realm entity);

    void setRegistrationAllowed(Realm entity, boolean registrationAllowed);

    boolean isRegistrationEmailAsUsername(Realm entity);

    void setRegistrationEmailAsUsername(Realm entity, boolean registrationEmailAsUsername);

    boolean isRememberMe(Realm entity);

    void setRememberMe(Realm entity, boolean rememberMe);

    String getDefaultSignatureAlgorithm(Realm entity);

    void setDefaultSignatureAlgorithm(Realm entity, String defaultSignatureAlgorithm);

    boolean isBruteForceProtected(Realm entity);

    void setBruteForceProtected(Realm entity, boolean value);

    boolean isPermanentLockout(Realm entity);

    void setPermanentLockout(Realm entity, boolean val);

    int getMaxFailureWaitSeconds(Realm entity);

    void setMaxFailureWaitSeconds(Realm entity, int val);

    int getWaitIncrementSeconds(Realm entity);

    void setWaitIncrementSeconds(Realm entity, int val);

    int getMinimumQuickLoginWaitSeconds(Realm entity);

    void setMinimumQuickLoginWaitSeconds(Realm entity, int val);

    long getQuickLoginCheckMilliSeconds(Realm entity);

    void setQuickLoginCheckMilliSeconds(Realm entity, long val);

    int getMaxDeltaTimeSeconds(Realm entity);

    void setMaxDeltaTimeSeconds(Realm entity, int val);

    int getFailureFactor(Realm entity);

    void setFailureFactor(Realm entity, int failureFactor);

    boolean isVerifyEmail(Realm entity);

    void setVerifyEmail(Realm entity, boolean verifyEmail);

    boolean isLoginWithEmailAllowed(Realm entity);

    void setLoginWithEmailAllowed(Realm entity, boolean loginWithEmailAllowed);

    boolean isDuplicateEmailsAllowed(Realm entity);

    void setDuplicateEmailsAllowed(Realm entity, boolean duplicateEmailsAllowed);

    boolean isResetPasswordAllowed(Realm entity);

    void setResetPasswordAllowed(Realm entity, boolean resetPasswordAllowed);

    boolean isRevokeRefreshToken(Realm entity);

    void setRevokeRefreshToken(Realm entity, boolean revokeRefreshToken);

    int getRefreshTokenMaxReuse(Realm entity);

    void setRefreshTokenMaxReuse(Realm entity, int revokeRefreshTokenCount);

    int getSsoSessionIdleTimeout(Realm entity);

    void setSsoSessionIdleTimeout(Realm entity, int seconds);

    int getSsoSessionMaxLifespan(Realm entity);

    void setSsoSessionMaxLifespan(Realm entity, int seconds);

    int getSsoSessionIdleTimeoutRememberMe(Realm entity);

    void setSsoSessionIdleTimeoutRememberMe(Realm entity, int seconds);

    int getSsoSessionMaxLifespanRememberMe(Realm entity);

    void setSsoSessionMaxLifespanRememberMe(Realm entity, int seconds);

    int getOfflineSessionIdleTimeout(Realm entity);

    void setOfflineSessionIdleTimeout(Realm entity, int seconds);

    int getAccessTokenLifespan(Realm entity);

    void setAccessTokenLifespan(Realm entity, int seconds);

    boolean isOfflineSessionMaxLifespanEnabled(Realm entity);

    void setOfflineSessionMaxLifespanEnabled(Realm entity, boolean offlineSessionMaxLifespanEnabled);

    int getOfflineSessionMaxLifespan(Realm entity);

    void setOfflineSessionMaxLifespan(Realm entity, int seconds);

    int getAccessTokenLifespanForImplicitFlow(Realm entity);

    void setAccessTokenLifespanForImplicitFlow(Realm entity, int seconds);

    int getAccessCodeLifespan(Realm entity);

    void setAccessCodeLifespan(Realm entity, int seconds);

    int getAccessCodeLifespanUserAction(Realm entity);

    void setAccessCodeLifespanUserAction(Realm entity, int seconds);

    Map<String, Integer> getUserActionTokenLifespans(Realm entity);

    int getAccessCodeLifespanLogin(Realm entity);

    void setAccessCodeLifespanLogin(Realm entity, int seconds);

    int getActionTokenGeneratedByAdminLifespan(Realm entity);

    void setActionTokenGeneratedByAdminLifespan(Realm entity, int seconds);

    int getActionTokenGeneratedByUserLifespan(Realm entity);

    void setActionTokenGeneratedByUserLifespan(Realm entity, int seconds);

    int getActionTokenGeneratedByUserLifespan(Realm entity, String actionTokenType);

    void setActionTokenGeneratedByUserLifespan(Realm entity, String actionTokenType, Integer seconds);

    void setAttribute(Realm entity, String name, String value);

    void setAttribute(Realm entity, String name, Boolean value);

    void setAttribute(Realm entity, String name, Integer value);

    void setAttribute(Realm entity, String name, Long value);

    void removeAttribute(Realm entity, String name);

    String getAttribute(Realm entity, String name);

    Integer getAttribute(Realm entity, String name, Integer defaultValue);

    Long getAttribute(Realm entity, String name, Long defaultValue);

    Boolean getAttribute(Realm entity, String name, Boolean defaultValue);

    Map<String, String> getAttributes(Realm entity);

    List<String> getRealmsWithProviderType(Class<?> providerType);

    List<String> getAllRealmIds();

    List<String> getRealmIdByName(String name);
}
