package org.keycloak.core.repository;

import org.keycloak.core.entity.UserFederationProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserFederationProviderRepository extends JpaRepository<UserFederationProvider, String>,
        JpaSpecificationExecutor<UserFederationProvider> {
}
