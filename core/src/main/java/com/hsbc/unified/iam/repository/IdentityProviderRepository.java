package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.IdentityProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface IdentityProviderRepository extends JpaRepository<IdentityProvider, String>,
        JpaSpecificationExecutor<IdentityProvider> {
}
