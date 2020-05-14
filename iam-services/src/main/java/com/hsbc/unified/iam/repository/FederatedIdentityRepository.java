package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.FederatedIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentity, FederatedIdentity.Key>,
        JpaSpecificationExecutor<FederatedIdentity> {
}
