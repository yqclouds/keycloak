package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.DefaultClientScopeRealmMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultClientScopeRealmMappingRepository extends JpaRepository<DefaultClientScopeRealmMapping, DefaultClientScopeRealmMapping.Key>,
        JpaSpecificationExecutor<DefaultClientScopeRealmMapping> {
}
