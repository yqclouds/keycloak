package org.keycloak.core.repository;

import org.keycloak.core.entity.UserGroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserGroupMembershipRepository extends JpaRepository<UserGroupMembership, UserGroupMembership.Key>,
        JpaSpecificationExecutor<UserGroupMembership> {
}
