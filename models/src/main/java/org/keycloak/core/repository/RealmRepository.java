package org.keycloak.core.repository;

import org.keycloak.core.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface RealmRepository extends JpaRepository<Realm, String>, JpaSpecificationExecutor<Realm> {
}
