package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.ClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeRepository extends JpaRepository<ClientScope, String>,
        JpaSpecificationExecutor<ClientScope> {
}
