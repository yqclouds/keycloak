package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.AuthenticationExecution;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuthenticationExecutionRepository extends JpaRepository<AuthenticationExecution, String>,
        JpaSpecificationExecutor<AuthenticationExecution> {
    @Query(name = "authenticationFlowExecution", value = "select authExec from AuthenticationExecution authExec where authExec.flowId = :flowId")
    List<AuthenticationExecution> authenticationFlowExecution(String flowId);
}
