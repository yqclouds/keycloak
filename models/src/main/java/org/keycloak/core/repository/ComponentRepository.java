package org.keycloak.core.repository;

import org.keycloak.core.entity.Component;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ComponentRepository extends JpaRepository<Component, String>,
        JpaSpecificationExecutor<Component> {
}
