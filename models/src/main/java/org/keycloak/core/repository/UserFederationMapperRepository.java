package org.keycloak.core.repository;

import org.keycloak.core.entity.UserFederationMapper;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserFederationMapperRepository extends JpaRepository<UserFederationMapper, String>,
        JpaSpecificationExecutor<UserFederationMapper> {
}
