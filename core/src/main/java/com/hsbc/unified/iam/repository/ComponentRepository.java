package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.Component;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ComponentRepository extends JpaRepository<Component, String>,
        JpaSpecificationExecutor<Component> {
}
