package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.AuthenticationExecution;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationExecutionRepository extends JpaRepository<AuthenticationExecution, String>,
        JpaSpecificationExecutor<AuthenticationExecution> {
}
