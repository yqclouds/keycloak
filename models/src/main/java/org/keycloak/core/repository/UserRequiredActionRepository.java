package org.keycloak.core.repository;

import org.keycloak.core.entity.UserRequiredAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRequiredActionRepository extends JpaRepository<UserRequiredAction, UserRequiredAction.Key>,
        JpaSpecificationExecutor<UserRequiredAction> {
}
