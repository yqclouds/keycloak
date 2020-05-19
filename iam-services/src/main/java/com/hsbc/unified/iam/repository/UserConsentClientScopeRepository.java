package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.User;
import com.hsbc.unified.iam.entity.UserConsentClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserConsentClientScopeRepository extends JpaRepository<UserConsentClientScope, UserConsentClientScope.Key>,
        JpaSpecificationExecutor<UserConsentClientScope> {
    @Query(name = "deleteUserConsentClientScopesByRealm", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user IN (select user from User user where user.realmId = :realmId))")
    void deleteUserConsentClientScopesByRealm(String realmId);

    @Query(name = "deleteUserConsentClientScopesByRealmAndLink", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link))")
    void deleteUserConsentClientScopesByRealmAndLink(String realmId, String link);

    @Query(name = "deleteUserConsentClientScopesByUser", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user = :user)")
    void deleteUserConsentClientScopesByUser(User user);

    @Query(name = "deleteUserConsentClientScopesByClientScope", value = "delete from UserConsentClientScope grantedScope where grantedScope.scopeId = :scopeId")
    void deleteUserConsentClientScopesByClientScope(String scopeId);

    @Query(name = "deleteUserConsentClientScopesByClient", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientId = :clientId)")
    void deleteUserConsentClientScopesByClient(String clientId);

    @Query(name = "deleteUserConsentClientScopesByExternalClient", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId)")
    void deleteUserConsentClientScopesByExternalClient(String clientStorageProvider, String externalClientId);

    @Query(name = "deleteUserConsentClientScopesByClientStorageProvider", value = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider)")
    void deleteUserConsentClientScopesByClientStorageProvider(String clientStorageProvider);
}
