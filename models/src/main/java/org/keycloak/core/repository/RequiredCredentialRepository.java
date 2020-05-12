package org.keycloak.core.repository;

import org.keycloak.core.entity.RealmRequiredCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface RequiredCredentialRepository extends JpaRepository<RealmRequiredCredential, RealmRequiredCredential.Key>,
        JpaSpecificationExecutor<RealmRequiredCredential> {
}
