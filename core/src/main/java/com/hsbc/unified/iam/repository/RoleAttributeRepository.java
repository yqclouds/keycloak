package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.RoleAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleAttributeRepository extends JpaRepository<RoleAttribute, String>,
        JpaSpecificationExecutor<RoleAttribute> {
    @Query(name = "deleteRoleAttributesByNameAndUser", value = "delete from RoleAttribute attr where attr.role.id = :roleId and attr.name = :name")
    void deleteRoleAttributesByNameAndUser(String roleId, String name);
}
