package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.ClientScopeRoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeRoleMappingRepository extends JpaRepository<ClientScopeRoleMapping, ClientScopeRoleMapping.Key>,
        JpaSpecificationExecutor<ClientScopeRoleMapping> {
}
