package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.ClientScopeClientMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeClientMappingRepository extends JpaRepository<ClientScopeClientMapping, ClientScopeClientMapping.Key>,
        JpaSpecificationExecutor<ClientScopeClientMapping> {
}
