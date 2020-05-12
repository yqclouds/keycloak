package org.keycloak.core.repository;

import org.keycloak.core.entity.ComponentConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ComponentConfigRepository extends JpaRepository<ComponentConfig, String>,
        JpaSpecificationExecutor<ComponentConfig> {
}
