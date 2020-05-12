package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.UserFederationProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserFederationProviderRepository extends JpaRepository<UserFederationProvider, String>,
        JpaSpecificationExecutor<UserFederationProvider> {
}
