package org.keycloak.core.repository;

import org.keycloak.core.entity.GroupRoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupRoleMappingRepository extends JpaRepository<GroupRoleMapping, GroupRoleMapping.Key>,
        JpaSpecificationExecutor<GroupRoleMapping> {
}
