package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ClientScopeAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeAttributeRepository extends JpaRepository<ClientScopeAttribute, ClientScopeAttribute.Key>,
        JpaSpecificationExecutor<ClientScopeAttribute> {
}
