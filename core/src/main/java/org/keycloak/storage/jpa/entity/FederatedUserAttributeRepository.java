package org.keycloak.storage.jpa.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserAttributeRepository extends JpaRepository<FederatedUserAttribute, String>,
        JpaSpecificationExecutor<FederatedUserAttribute> {
    @Query(name = "getFederatedAttributesByNameAndValue", value = "select attr.userId from FederatedUserAttribute attr where attr.name = :name and attr.value = :value and attr.realmId=:realmId")
    List<String> getFederatedAttributesByNameAndValue(String realmId, String name, String value);

    @Query(name = "getFederatedAttributesByUser", value = "select attr from FederatedUserAttribute attr where attr.userId = :userId and attr.realmId=:realmId")
    List<FederatedUserAttribute> getFederatedAttributesByUser(String realmId, String userId);

    @Query(name = "deleteUserFederatedAttributesByUser", value = "delete from  FederatedUserAttribute attr where attr.userId = :userId and attr.realmId=:realmId")
    int deleteUserFederatedAttributesByUser(String userId, String realmId);

    @Query(name = "deleteUserFederatedAttributesByUserAndName", value = "delete from  FederatedUserAttribute attr where attr.userId = :userId and attr.name=:name and attr.realmId=:realmId")
    int deleteUserFederatedAttributesByUserAndName(String realmId, String userId, String name);

    @Query(name = "deleteUserFederatedAttributesByRealm", value = "delete from  FederatedUserAttribute attr where attr.realmId=:realmId")
    int deleteUserFederatedAttributesByRealm(String realmId);

    @Query(name = "deleteFederatedAttributesByStorageProvider", value = "delete from FederatedUserAttribute e where e.storageProviderId=:storageProviderId")
    int deleteFederatedAttributesByStorageProvider(String storageProviderId);

    @Query(name = "deleteUserFederatedAttributesByRealmAndLink", value = "delete from  FederatedUserAttribute attr where attr.userId IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    int deleteUserFederatedAttributesByRealmAndLink();
}
