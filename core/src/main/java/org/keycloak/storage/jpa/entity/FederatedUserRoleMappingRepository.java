package org.keycloak.storage.jpa.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserRoleMappingRepository extends JpaRepository<FederatedUserRoleMapping, FederatedUserRoleMapping.Key>,
        JpaSpecificationExecutor<FederatedUserRoleMapping> {
    @Query(name = "feduserHasRole", value = "select m from FederatedUserRoleMapping m where m.userId = :userId and m.roleId = :roleId")
    List<FederatedUserRoleMapping> feduserHasRole();

    @Query(name = "feduserRoleMappings", value = "select m from FederatedUserRoleMapping m where m.userId = :userId")
    List<FederatedUserRoleMapping> feduserRoleMappings(String userId);

    @Query(name = "deleteFederatedUserRoleMappingsByRealm", value = "delete from  FederatedUserRoleMapping mapping where mapping.realmId=:realmId")
    void deleteFederatedUserRoleMappingsByRealm(String realmId);

    @Query(name = "deleteFederatedUserRoleMappingsByStorageProvider", value = "delete from FederatedUserRoleMapping e where e.storageProviderId=:storageProviderId")
    void deleteFederatedUserRoleMappingsByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserRoleMappingsByRealmAndLink", value = "delete from  FederatedUserRoleMapping mapping where mapping.userId IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteFederatedUserRoleMappingsByRealmAndLink();

    @Query(name = "deleteFederatedUserRoleMappingsByRole", value = "delete from FederatedUserRoleMapping m where m.roleId = :roleId")
    void deleteFederatedUserRoleMappingsByRole(String roleId);

    @Query(name = "deleteFederatedUserRoleMappingsByUser", value = "delete from FederatedUserRoleMapping m where m.userId = :userId and m.realmId = :realmId")
    void deleteFederatedUserRoleMappingsByUser(String userId, String realmId);
}
