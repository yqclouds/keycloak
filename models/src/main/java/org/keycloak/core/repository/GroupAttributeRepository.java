package org.keycloak.core.repository;

import org.keycloak.core.entity.GroupAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupAttributeRepository extends JpaRepository<GroupAttribute, String>,
        JpaSpecificationExecutor<GroupAttribute> {
}
