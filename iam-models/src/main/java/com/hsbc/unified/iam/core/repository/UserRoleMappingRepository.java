package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.UserRoleMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleMappingRepository extends JpaRepository<UserRoleMapping, UserRoleMapping.Key>,
        JpaSpecificationExecutor<UserRoleMapping> {
}