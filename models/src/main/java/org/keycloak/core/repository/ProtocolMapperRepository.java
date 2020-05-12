package org.keycloak.core.repository;

import org.keycloak.core.entity.ProtocolMapper;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ProtocolMapperRepository extends JpaRepository<ProtocolMapper, String>,
        JpaSpecificationExecutor<ProtocolMapper> {
}
