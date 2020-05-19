package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ComponentConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ComponentConfigRepository extends JpaRepository<ComponentConfig, String>,
        JpaSpecificationExecutor<ComponentConfig> {
}
