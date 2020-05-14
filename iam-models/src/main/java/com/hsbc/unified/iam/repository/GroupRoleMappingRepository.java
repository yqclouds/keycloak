package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.Group;
import com.hsbc.unified.iam.entity.GroupRoleMapping;
import com.hsbc.unified.iam.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GroupRoleMappingRepository extends JpaRepository<GroupRoleMapping, GroupRoleMapping.Key>,
        JpaSpecificationExecutor<GroupRoleMapping> {
    @Modifying
    @Query(name = "deleteGroupRoleMappingsByRealm", value = "delete from  GroupRoleMapping mapping where mapping.group IN (select u from Group u where u.realm=:realm)")
    void deleteGroupRoleMappingsByRealm(@Param("realm") Realm realm);

    @Query(name = "groupsInRole", value = "select g from GroupRoleMapping m, Group g where m.roleId=:roleId and g.id=m.group")
    List<Group> findGroupsInRole(String roleId);

    @Query(name = "groupHasRole", value = "select m from GroupRoleMapping m where m.group = :group and m.roleId = :roleId")
    boolean isGroupHasRole(Group group, String roleId);

    @Query(name = "groupRoleMappings", value = "select m from GroupRoleMapping m where m.group = :group")
    List<GroupRoleMapping> findGroupRoleMappings(Group group);

    @Query(name = "groupRoleMappingIds", value = "select m.roleId from GroupRoleMapping m where m.group = :group")
    List<String> findGroupRoleMappingIds(Group group);

    @Modifying
    @Query(name = "deleteGroupRoleMappingsByRole", value = "delete from GroupRoleMapping m where m.roleId = :roleId")
    void deleteGroupRoleMappingsByRole(String roleId);

    @Modifying
    @Query(name = "deleteGroupRoleMappingsByGroup", value = "delete from GroupRoleMapping m where m.group = :group")
    void deleteGroupRoleMappingsByGroup(Group group);
}
