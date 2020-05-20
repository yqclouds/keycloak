package org.keycloak.authorization.jpa.entities;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResourceRepository extends JpaRepository<Resource, String>, JpaSpecificationExecutor<Resource> {
    @Query(name = "findResourceIdByOwner", value = "select distinct(r) from Resource r left join fetch r.scopes s where r.resourceServer.id = :serverId and r.owner = :owner")
    List<Resource> findResourceIdByOwner(String serverId, String owner);

    @Query(name = "findResourceIdByOwnerOrdered", value = "select distinct(r) from Resource r left join fetch r.scopes s where r.resourceServer.id = :serverId and r.owner = :owner order by r.id")
    List<Resource> findResourceIdByOwnerOrdered(String serverId, String owner);

    @Query(name = "findAnyResourceIdByOwner", value = "select distinct(r) from Resource r left join fetch r.scopes s where r.owner = :owner")
    List<Resource> findAnyResourceIdByOwner(String owner);

    @Query(name = "findAnyResourceIdByOwnerOrdered", value = "select distinct(r) from Resource r left join fetch r.scopes s where r.owner = :owner order by r.id")
    List<Resource> findAnyResourceIdByOwnerOrdered(String owner);

    @Query(name = "findResourceIdByUri", value = "select r.id from Resource r where  r.resourceServer.id = :serverId  and :uri in elements(r.uris)")
    List<String> findResourceIdByUri(String uri, String serverId);

    @Query(name = "findResourceIdByName", value = "select distinct(r) from Resource r left join fetch r.scopes s where  r.resourceServer.id = :serverId  and r.owner = :ownerId and r.name = :name")
    Resource findResourceIdByName(String serverId, String name, String ownerId);

    @Query(name = "findResourceIdByType", value = "select distinct(r) from Resource r left join fetch r.scopes s where  r.resourceServer.id = :serverId  and r.owner = :ownerId and r.type = :type")
    List<Resource> findResourceIdByType(String type);

    @Query(name = "findResourceIdByTypeNoOwner", value = "select distinct(r) from Resource r left join fetch r.scopes s where  r.resourceServer.id = :serverId  and r.type = :type")
    List<Resource> findResourceIdByTypeNoOwner(String type, String serverId);

    @Query(name = "findResourceIdByTypeInstance", value = "select distinct(r) from Resource r left join fetch r.scopes s where  r.resourceServer.id = :serverId and r.type = :type and r.owner <> :serverId")
    List<Resource> findResourceIdByTypeInstance(String type, String serverId);

    @Query(name = "findResourceIdByServerId", value = "select r.id from Resource r where  r.resourceServer.id = :serverId ")
    List<String> findResourceIdByServerId(String serverId);

    @Query(name = "findResourceIdByScope", value = "select r from Resource r inner join r.scopes s where r.resourceServer.id = :serverId and (s.resourceServer.id = :serverId and s.id in (:scopeIds))")
    List<Resource> findResourceIdByScope(List<String> scopes, String resourceServerId);

    @Query(name = "deleteResourceByResourceServer", value = "delete from Resource r where r.resourceServer.id = :serverId")
    void deleteResourceByResourceServer();
}
