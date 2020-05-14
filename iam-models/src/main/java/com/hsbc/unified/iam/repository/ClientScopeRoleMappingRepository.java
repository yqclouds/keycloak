package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ClientScope;
import com.hsbc.unified.iam.entity.ClientScopeRoleMapping;
import com.hsbc.unified.iam.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClientScopeRoleMappingRepository extends JpaRepository<ClientScopeRoleMapping, ClientScopeRoleMapping.Key>,
        JpaSpecificationExecutor<ClientScopeRoleMapping> {
    @Query(name = "clientScopeHasRole", value = "select m from ClientScopeRoleMapping m where m.clientScope = :clientScope and m.role = :role")
    List<ClientScopeRoleMapping> clientScopeHasRole(ClientScope clientScope, Role role);

    @Query(name = "clientScopeRoleMappingIds", value = "select m.role.id from ClientScopeRoleMapping m where m.clientScope = :clientScope")
    List<String> clientScopeRoleMappingIds(ClientScope clientScope);

    @Query(name = "deleteClientScopeRoleMappingByRole", value = "delete from ClientScopeRoleMapping where role = :role")
    void deleteClientScopeRoleMappingByRole(Role role);

    @Query(name = "deleteClientScopeRoleMappingByClientScope", value = "delete from ClientScopeRoleMapping where clientScope = :clientScope")
    void deleteClientScopeRoleMappingByClientScope(ClientScope clientScope);
}
