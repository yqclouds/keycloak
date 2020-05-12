package org.keycloak.core.repository;

import org.keycloak.core.entity.AuthenticationFlow;
import org.keycloak.core.entity.AuthenticatorConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationFlowRepository extends JpaRepository<AuthenticationFlow, String>,
        JpaSpecificationExecutor<AuthenticationFlow> {
}
