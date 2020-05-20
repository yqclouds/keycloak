package org.keycloak.storage.jpa.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserCredentialRepository extends JpaRepository<FederatedUserCredential, String>,
        JpaSpecificationExecutor<FederatedUserCredential> {
    @Query(name = "federatedUserCredentialByUser", value = "select cred from FederatedUserCredential cred where cred.userId = :userId order by cred.priority")
    List<FederatedUserCredential> federatedUserCredentialByUser(String userId);

    @Query(name = "federatedUserCredentialByUserAndType", value = "select cred from FederatedUserCredential cred where cred.userId = :userId and cred.type = :type order by cred.priority")
    List<FederatedUserCredential> federatedUserCredentialByUserAndType(String type, String userId);

    @Query(name = "federatedUserCredentialByNameAndType", value = "select cred from FederatedUserCredential cred where cred.userId = :userId and cred.type = :type and cred.userLabel = :userLabel order by cred.priority")
    List<FederatedUserCredential> federatedUserCredentialByNameAndType(String type, String userLabel, String userId);

    @Query(name = "deleteFederatedUserCredentialByUser", value = "delete from FederatedUserCredential cred where cred.userId = :userId and cred.realmId = :realmId")
    void deleteFederatedUserCredentialByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUserCredentialByUserAndType", value = "delete from FederatedUserCredential cred where cred.userId = :userId and cred.type = :type")
    void deleteFederatedUserCredentialByUserAndType();

    @Query(name = "deleteFederatedUserCredentialByUserAndTypeAndUserLabel", value = "delete from FederatedUserCredential cred where cred.userId = :userId and cred.type = :type and cred.userLabel = :userLabel")
    void deleteFederatedUserCredentialByUserAndTypeAndUserLabel();

    @Query(name = "deleteFederatedUserCredentialsByRealm", value = "delete from FederatedUserCredential cred where cred.realmId=:realmId")
    void deleteFederatedUserCredentialsByRealm(String realmId);

    @Query(name = "deleteFederatedUserCredentialsByStorageProvider", value = "delete from FederatedUserCredential cred where cred.storageProviderId=:storageProviderId")
    void deleteFederatedUserCredentialsByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserCredentialsByRealmAndLink", value = "delete from FederatedUserCredential cred where cred.userId IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteFederatedUserCredentialsByRealmAndLink();
}
