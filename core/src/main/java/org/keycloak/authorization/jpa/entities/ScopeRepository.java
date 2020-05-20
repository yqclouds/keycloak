package org.keycloak.authorization.jpa.entities;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScopeRepository extends JpaRepository<Scope, String>, JpaSpecificationExecutor<Scope> {
    @Query(name = "findScopeIdByName", value = "select s.id from ScopeModel s where s.resourceServer.id = :serverId and s.name = :name")
    String findScopeIdByName(String serverId, String name);

    @Query(name = "findScopeIdByResourceServer", value = "select s.id from ScopeModel s where s.resourceServer.id = :serverId")
    List<String> findScopeIdByResourceServer(String serverId);

    @Query(name = "deleteScopeByResourceServer", value = "delete from ScopeModel s where s.resourceServer.id = :serverId")
    int deleteScopeByResourceServer();
}
