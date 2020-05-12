package org.keycloak.core.repository;

import org.keycloak.core.entity.ClientScopeRoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeRoleMappingRepository extends JpaRepository<ClientScopeRoleMapping, ClientScopeRoleMapping.Key>,
        JpaSpecificationExecutor<ClientScopeRoleMapping> {
}
