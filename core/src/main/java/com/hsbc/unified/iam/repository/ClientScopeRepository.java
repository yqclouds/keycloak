package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientScopeRepository extends JpaRepository<ClientScope, String>,
        JpaSpecificationExecutor<ClientScope> {
}
