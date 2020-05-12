package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.IdentityProviderMapper;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface IdentityProviderMapperRepository extends JpaRepository<IdentityProviderMapper, String>,
        JpaSpecificationExecutor<IdentityProviderMapper> {
}
