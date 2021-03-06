package com.hsbc.unified.iam.repository.authorization;

import com.hsbc.unified.iam.entity.authorization.ResourceAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface ResourceAttributeRepository extends JpaRepository<ResourceAttribute, String>, JpaSpecificationExecutor<ResourceAttribute> {
    @Query(name = "deleteResourceAttributesByNameAndResource", value = "delete from ResourceAttribute attr where attr.resource.id = :resourceId and attr.name = :name")
    void deleteResourceAttributesByNameAndResource(String name, String resourceId);
}
