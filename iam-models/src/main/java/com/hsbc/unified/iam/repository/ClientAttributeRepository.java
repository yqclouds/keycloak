package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ClientAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientAttributeRepository extends JpaRepository<ClientAttribute, ClientAttribute.Key>,
        JpaSpecificationExecutor<ClientAttribute> {
}
