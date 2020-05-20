package com.hsbc.unified.iam.repository.authorization;

import com.hsbc.unified.iam.entity.authorization.ResourceServer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ResourceServerRepository extends JpaRepository<ResourceServer, String>, JpaSpecificationExecutor<ResourceServer> {
}
