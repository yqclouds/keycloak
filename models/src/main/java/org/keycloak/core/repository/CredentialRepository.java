package org.keycloak.core.repository;

import org.keycloak.core.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, String>,
        JpaSpecificationExecutor<Credential> {
}
