package com.hsbc.unified.iam.repository.storage;

import com.hsbc.unified.iam.entity.storage.FederatedUserConsentClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface FederatedUserConsentClientScopeRepository extends JpaRepository<FederatedUserConsentClientScope, FederatedUserConsentClientScope.Key>,
        JpaSpecificationExecutor<FederatedUserConsentClientScope> {
    @Query(name = "deleteFederatedUserConsentClientScopesByRealm", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.realmId = :realmId)")
    void deleteFederatedUserConsentClientScopesByRealm(String realmId);

    @Query(name = "deleteFederatedUserConsentClientScopesByUser", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.userId = :userId and consent.realmId = :realmId)")
    void deleteFederatedUserConsentClientScopesByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUserConsentClientScopesByStorageProvider", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.storageProviderId = :storageProviderId)")
    void deleteFederatedUserConsentClientScopesByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserConsentClientScopesByClientScope", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.scopeId = :scopeId")
    void deleteFederatedUserConsentClientScopesByClientScope(String scopeId);

    @Query(name = "deleteFederatedUserConsentClientScopesByClient", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.clientId = :clientId)")
    void deleteFederatedUserConsentClientScopesByClient(String clientId);

    @Query(name = "deleteFederatedUserConsentClientScopesByExternalClient", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId)")
    void deleteFederatedUserConsentClientScopesByExternalClient(String clientStorageProvider, String externalClientId);

    @Query(name = "deleteFederatedUserConsentClientScopesByClientStorageProvider", value = "delete from FederatedUserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from FederatedUserConsent consent where consent.clientStorageProvider = :clientStorageProvider)")
    void deleteFederatedUserConsentClientScopesByClientStorageProvider(String clientStorageProvider);
}
