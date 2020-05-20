package org.keycloak.authorization.jpa.entities;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PermissionTicketRepository
        extends JpaRepository<PermissionTicket, String>, JpaSpecificationExecutor<PermissionTicket> {
    @Query(name = "findPermissionIdByResource", value = "select p.id from PermissionTicketModel p inner join p.resource r where p.resourceServer.id = :serverId and (r.resourceServer.id = :serverId and r.id = :resourceId)")
    List<String> findPermissionIdByResource(String resourceId, String serverId);

    @Query(name = "findPermissionIdByScope", value = "select p.id from PermissionTicketModel p inner join p.scope s where p.resourceServer.id = :serverId and (s.resourceServer.id = :serverId and s.id = :scopeId)")
    List<String> findPermissionIdByScope(String scopeId, String serverId);

    @Query(name = "findPermissionTicketIdByServerId", value = "select p.id from PermissionTicketModel p where  p.resourceServer.id = :serverId ")
    List<String> findPermissionTicketIdByServerId(String serverId);

    @Query(name = "findGrantedResources", value = "select distinct(r.id) from ResourceModel r inner join PermissionTicketModel p on r.id = p.resource.id where p.grantedTimestamp is not null and p.requester = :requester order by r.id")
    List<String> findGrantedResources(String requester);

    @Query(name = "findGrantedResourcesByName", value = "select distinct(r.id) from ResourceModel r inner join PermissionTicketModel p on r.id = p.resource.id where p.grantedTimestamp is not null and p.requester = :requester and lower(r.name) like :resourceName order by r.id")
    List<String> findGrantedResourcesByName(String requester, String resourceName);

    @Query(name = "findGrantedOwnerResources", value = "select distinct(r.id) from ResourceModel r inner join PermissionTicketModel p on r.id = p.resource.id where p.grantedTimestamp is not null and p.owner = :owner order by r.id")
    List<String> findGrantedOwnerResources(String owner);
}
