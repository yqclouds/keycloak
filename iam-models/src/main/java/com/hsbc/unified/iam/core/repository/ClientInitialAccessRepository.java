package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.ClientInitialAccess;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientInitialAccessRepository extends JpaRepository<ClientInitialAccess, String>,
        JpaSpecificationExecutor<ClientInitialAccess> {
}
