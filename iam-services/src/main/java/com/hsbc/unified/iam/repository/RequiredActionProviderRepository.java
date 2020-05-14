package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.RequiredActionProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface RequiredActionProviderRepository extends JpaRepository<RequiredActionProvider, String>,
        JpaSpecificationExecutor<RequiredActionProvider> {
}
