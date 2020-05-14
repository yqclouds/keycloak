package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserConsentRepository extends JpaRepository<UserConsent, String>,
        JpaSpecificationExecutor<UserConsent> {
}
