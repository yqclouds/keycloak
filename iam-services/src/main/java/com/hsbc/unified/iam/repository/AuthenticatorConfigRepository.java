package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.AuthenticatorConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticatorConfigRepository extends JpaRepository<AuthenticatorConfig, String>,
        JpaSpecificationExecutor<AuthenticatorConfig> {
}
