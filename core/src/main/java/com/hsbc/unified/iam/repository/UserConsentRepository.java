package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.User;
import com.hsbc.unified.iam.entity.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserConsentRepository extends JpaRepository<UserConsent, String>,
        JpaSpecificationExecutor<UserConsent> {
    @Query(name = "userConsentByUserAndClient", value = "select consent from UserConsent consent where consent.user.id = :userId and consent.clientId = :clientId")
    List<UserConsent> userConsentByUserAndClient(String userId, String clientId);

    @Query(name = "userConsentByUserAndExternalClient", value = "select consent from UserConsent consent where consent.user.id = :userId and consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId")
    List<UserConsent> userConsentByUserAndExternalClient(String userId, String clientStorageProvider, String externalClientId);

    @Query(name = "userConsentsByUser", value = "select consent from UserConsent consent where consent.user.id = :userId")
    List<UserConsent> userConsentsByUser(String userId);

    @Query(name = "deleteUserConsentsByRealm", value = "delete from UserConsent consent where consent.user IN (select user from User user where user.realmId = :realmId)")
    void deleteUserConsentsByRealm(String realmId);

    @Query(name = "deleteUserConsentsByRealmAndLink", value = "delete from UserConsent consent where consent.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteUserConsentsByRealmAndLink(String realmId, String link);

    @Query(name = "deleteUserConsentsByUser", value = "delete from UserConsent consent where consent.user = :user")
    void deleteUserConsentsByUser(User user);

    @Query(name = "deleteUserConsentsByClient", value = "delete from UserConsent consent where consent.clientId = :clientId")
    void deleteUserConsentsByClient(String clientId);

    @Query(name = "deleteUserConsentsByExternalClient", value = "delete from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId")
    void deleteUserConsentsByExternalClient(String clientStorageProvider, String externalClientId);

    @Query(name = "deleteUserConsentsByClientStorageProvider", value = "delete from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider")
    void deleteUserConsentsByClientStorageProvider(String clientStorageProvider);
}
