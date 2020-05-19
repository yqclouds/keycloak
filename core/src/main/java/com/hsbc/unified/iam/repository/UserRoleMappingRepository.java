package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.User;
import com.hsbc.unified.iam.entity.UserRoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRoleMappingRepository extends JpaRepository<UserRoleMapping, UserRoleMapping.Key>,
        JpaSpecificationExecutor<UserRoleMapping> {
    @Query(name = "usersInRole", value = "select u from UserRoleMapping m, User u where m.roleId=:roleId and u.id=m.user")
    List<User> usersInRole(String roleId);

    @Query(name = "userHasRole", value = "select m from UserRoleMapping m where m.user = :user and m.roleId = :roleId")
    List<UserRoleMapping> userHasRole(User user, String roleId);

    @Query(name = "userRoleMappings", value = "select m from UserRoleMapping m where m.user = :user")
    List<UserRoleMapping> userRoleMappings(User user);

    @Query(name = "userRoleMappingIds", value = "select m.roleId from UserRoleMapping m where m.user = :user")
    List<String> userRoleMappingIds(User user);

    @Query(name = "deleteUserRoleMappingsByRealm", value = "delete from  UserRoleMapping mapping where mapping.user IN (select u from User u where u.realmId=:realmId)")
    void deleteUserRoleMappingsByRealm(String realmId);

    @Query(name = "deleteUserRoleMappingsByRealmAndLink", value = "delete from  UserRoleMapping mapping where mapping.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteUserRoleMappingsByRealmAndLink(String realmId, String link);

    @Query(name = "deleteUserRoleMappingsByRole", value = "delete from UserRoleMapping m where m.roleId = :roleId")
    void deleteUserRoleMappingsByRole(String roleId);

    @Query(name = "deleteUserRoleMappingsByUser", value = "delete from UserRoleMapping m where m.user = :user")
    void deleteUserRoleMappingsByUser(User user);

    @Query(name = "grantRoleToAllUsers", value = "insert into UserRoleMapping (roleId, user) select role.id, user from Role role, User user where role.id = :roleId AND role.realm.id = :realmId AND user.realmId = :realmId")
    void grantRoleToAllUsers(String roleId, String realmId);
}
