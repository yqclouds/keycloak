package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.UserAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAttributeRepository extends JpaRepository<UserAttribute, String>,
        JpaSpecificationExecutor<UserAttribute> {
}