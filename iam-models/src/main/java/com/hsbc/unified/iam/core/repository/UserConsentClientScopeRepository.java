package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.UserConsentClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserConsentClientScopeRepository extends JpaRepository<UserConsentClientScope, UserConsentClientScope.Key>,
        JpaSpecificationExecutor<UserConsentClientScope> {
}
