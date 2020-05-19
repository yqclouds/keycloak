package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.User;
import com.hsbc.unified.iam.entity.UserGroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface UserGroupMembershipRepository extends JpaRepository<UserGroupMembership, UserGroupMembership.Key>,
        JpaSpecificationExecutor<UserGroupMembership> {
    @Query(name = "userMemberOf", value = "select m from UserGroupMembership m where m.user = :user and m.groupId = :groupId")
    List<UserGroupMembership> userMemberOf(User user, String groupId);

    @Query(name = "userGroupMembership", value = "select m from UserGroupMembership m where m.user = :user")
    List<UserGroupMembership> userGroupMembership(User user);

    @Query(name = "groupMembership", value = "select g.user from UserGroupMembership g where g.groupId = :groupId order by g.user.username")
    List<User> groupMembership(String groupId);

    @Query(name = "deleteUserGroupMembershipByRealm", value = "delete from  UserGroupMembership mapping where mapping.user IN (select u from User u where u.realmId=:realmId)")
    void deleteUserGroupMembershipByRealm(String realmId);

    @Query(name = "deleteUserGroupMembershipsByRealmAndLink", value = "delete from  UserGroupMembership mapping where mapping.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteUserGroupMembershipsByRealmAndLink(String realmId, String link);

    @Query(name = "deleteUserGroupMembershipsByGroup", value = "delete from UserGroupMembership m where m.groupId = :groupId")
    void deleteUserGroupMembershipsByGroup(String groupId);

    @Query(name = "deleteUserGroupMembershipsByUser", value = "delete from UserGroupMembership m where m.user = :user")
    void deleteUserGroupMembershipsByUser(User user);

    @Query(name = "searchForUserCountInGroups", value = "select count(m.user) from UserGroupMembership m where m.user.realmId = :realmId and (m.user.serviceAccountClientLink is null) and " +
            "( lower(m.user.username) like :search or lower(concat(m.user.firstName, ' ', m.user.lastName)) like :search or m.user.email like :search ) and m.group.id in :groupIds")
    Long searchForUserCountInGroups(String realmId, Collection<String> groupIds, String search);

    @Query(name = "userCountInGroups", value = "select count(m.user) from UserGroupMembership m where m.user.realmId = :realmId and m.group.id in :groupIds")
    Long userCountInGroups(String realmId, Collection<String> groupIds);
}
