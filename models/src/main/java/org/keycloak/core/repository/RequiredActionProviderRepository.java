package org.keycloak.core.repository;

import org.keycloak.core.entity.RequiredActionProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface RequiredActionProviderRepository extends JpaRepository<RequiredActionProvider, String>,
        JpaSpecificationExecutor<RequiredActionProvider> {
}
