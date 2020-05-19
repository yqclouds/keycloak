package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.GroupAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupAttributeRepository extends JpaRepository<GroupAttribute, String>,
        JpaSpecificationExecutor<GroupAttribute> {
}
