package org.keycloak.storage.jpa.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserRepository extends JpaRepository<FederatedUser, String>, JpaSpecificationExecutor<FederatedUser> {
    @Query(name = "getFederatedUserIds", value = "select f.id from FederatedUser f where f.realmId=:realmId")
    List<String> getFederatedUserIds(String realmId);

    @Query(name = "getFederatedUserCount", value = "select count(u) from FederatedUser u where u.realmId = :realmId")
    int getFederatedUserCount(String realmId);

    @Query(name = "deleteFederatedUserByUser", value = "delete from  FederatedUser f where f.id = :userId and f.realmId=:realmId")
    int deleteFederatedUserByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUsersByRealm", value = "delete from  FederatedUser f where f.realmId=:realmId")
    int deleteFederatedUsersByRealm(String realmId);

    @Query(name = "deleteFederatedUsersByStorageProvider", value = "delete from FederatedUser f where f.storageProviderId=:storageProviderId")
    int deleteFederatedUsersByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUsersByRealmAndLink", value = "delete from  FederatedUser f where f.id IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    int deleteFederatedUsersByRealmAndLink();
}
