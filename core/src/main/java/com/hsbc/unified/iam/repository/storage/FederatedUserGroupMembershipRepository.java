package com.hsbc.unified.iam.repository.storage;

import com.hsbc.unified.iam.entity.storage.FederatedUserGroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserGroupMembershipRepository extends JpaRepository<FederatedUserGroupMembership, FederatedUserGroupMembership.Key>,
        JpaSpecificationExecutor<FederatedUserGroupMembership> {
    @Query(name = "feduserMemberOf", value = "select m from FederatedUserGroupMembership m where m.userId = :userId and m.groupId = :groupId")
    List<FederatedUserGroupMembership> feduserMemberOf(String userId, String groupId);

    @Query(name = "feduserGroupMembership", value = "select m from FederatedUserGroupMembership m where m.userId = :userId")
    List<FederatedUserGroupMembership> feduserGroupMembership(String userId);

    @Query(name = "fedgroupMembership", value = "select g.userId from FederatedUserGroupMembership g where g.groupId = :groupId and g.realmId = :realmId")
    List<String> fedgroupMembership(String realmId, String groupId);

    @Query(name = "feduserGroupIds", value = "select m.groupId from FederatedUserGroupMembership m where m.userId = :userId")
    List<String> feduserGroupIds();

    @Query(name = "deleteFederatedUserGroupMembershipByRealm", value = "delete from  FederatedUserGroupMembership mapping where mapping.realmId=:realmId")
    void deleteFederatedUserGroupMembershipByRealm(String realmId);

    @Query(name = "deleteFederatedUserGroupMembershipByStorageProvider", value = "delete from FederatedUserGroupMembership e where e.storageProviderId=:storageProviderId")
    void deleteFederatedUserGroupMembershipByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserGroupMembershipsByRealmAndLink", value = "delete from  FederatedUserGroupMembership mapping where mapping.userId IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteFederatedUserGroupMembershipsByRealmAndLink();

    @Query(name = "deleteFederatedUserGroupMembershipsByGroup", value = "delete from FederatedUserGroupMembership m where m.groupId = :groupId")
    void deleteFederatedUserGroupMembershipsByGroup(String groupId);

    @Query(name = "deleteFederatedUserGroupMembershipsByUser", value = "delete from FederatedUserGroupMembership m where m.userId = :userId and m.realmId = :realmId")
    void deleteFederatedUserGroupMembershipsByUser(String userId, String realmId);
}
