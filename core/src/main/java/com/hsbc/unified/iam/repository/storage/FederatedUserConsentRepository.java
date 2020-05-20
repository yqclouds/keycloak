package com.hsbc.unified.iam.repository.storage;

import com.hsbc.unified.iam.entity.storage.FederatedUserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserConsentRepository extends JpaRepository<FederatedUserConsent, String>,
        JpaSpecificationExecutor<FederatedUserConsent> {
    @Query(name = "userFederatedConsentByUserAndClient", value = "select consent from FederatedUserConsent consent where consent.userId = :userId and consent.clientId = :clientId")
    List<FederatedUserConsent> userFederatedConsentByUserAndClient(String userId, String clientId);

    @Query(name = "userFederatedConsentByUserAndExternalClient", value = "select consent from FederatedUserConsent consent where consent.userId = :userId and consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId")
    List<FederatedUserConsent> userFederatedConsentByUserAndExternalClient(String userId, String clientStorageProvider, String externalClientId);

    @Query(name = "userFederatedConsentsByUser", value = "select consent from FederatedUserConsent consent where consent.userId = :userId")
    List<FederatedUserConsent> userFederatedConsentsByUser(String userId);

    @Query(name = "deleteFederatedUserConsentsByRealm", value = "delete from FederatedUserConsent consent where consent.realmId=:realmId")
    int deleteFederatedUserConsentsByRealm(String realmId);

    @Query(name = "deleteFederatedUserConsentsByStorageProvider", value = "delete from FederatedUserConsent e where e.storageProviderId=:storageProviderId")
    int deleteFederatedUserConsentsByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserConsentsByUser", value = "delete from FederatedUserConsent consent where consent.userId = :userId and consent.realmId = :realmId")
    int deleteFederatedUserConsentsByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUserConsentsByClient", value = "delete from FederatedUserConsent consent where consent.clientId = :clientId")
    int deleteFederatedUserConsentsByClient(String clientId);

    @Query(name = "deleteFederatedUserConsentsByExternalClient", value = "delete from FederatedUserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId")
    int deleteFederatedUserConsentsByExternalClient(String clientStorageProvider, String externalClientId);

    @Query(name = "deleteFederatedUserConsentsByClientStorageProvider", value = "delete from FederatedUserConsent consent where consent.clientStorageProvider = :clientStorageProvider")
    int deleteFederatedUserConsentsByClientStorageProvider(String clientStorageProvider);
}
