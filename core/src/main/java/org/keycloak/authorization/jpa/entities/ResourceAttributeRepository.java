package org.keycloak.authorization.jpa.entities;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface ResourceAttributeRepository extends JpaRepository<ResourceAttribute, String>, JpaSpecificationExecutor<ResourceAttribute> {
    @Query(name = "deleteResourceAttributesByNameAndResource", value = "delete from ResourceAttribute attr where attr.resource.id = :resourceId and attr.name = :name")
    void deleteResourceAttributesByNameAndResource();
}
