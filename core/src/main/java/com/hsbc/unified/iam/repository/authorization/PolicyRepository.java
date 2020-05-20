package com.hsbc.unified.iam.repository.authorization;

import com.hsbc.unified.iam.entity.authorization.Policy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, String>, JpaSpecificationExecutor<Policy> {
    @Query(name = "findPolicyIdByServerId", value = "select p.id from PolicyModel p where  p.resourceServer.id = :serverId ")
    List<String> findPolicyIdByServerId(String serverId);

    @Query(name = "findPolicyIdByName", value = "select p from PolicyModel p left join fetch p.associatedPolicies a where  p.resourceServer.id = :serverId  and p.name = :name")
    Policy findPolicyIdByName(String serverId, String name);

    @Query(name = "findPolicyIdByResource", value = "select p from PolicyModel p inner join fetch p.resources r left join fetch p.scopes s inner join fetch p.associatedPolicies a where p.resourceServer.id = :serverId and (r.resourceServer.id = :serverId and r.id = :resourceId)")
    List<Policy> findPolicyIdByResource(String resourceId, String serverId);

    @Query(name = "findPolicyIdByScope", value = "select pe from PolicyModel pe left join fetch pe.resources r inner join fetch pe.scopes s inner join fetch pe.associatedPolicies a where pe.resourceServer.id = :serverId and exists (select p.id from ScopeModel s inner join s.policies p where s.resourceServer.id = :serverId and (p.resourceServer.id = :serverId and p.type = 'scope' and s.id in (:scopeIds) and p.id = pe.id))")
    List<Policy> findPolicyIdByScope(Collection<String> scopeIds, String resourceServerId);

    @Query(name = "findPolicyIdByResourceScope", value = "select pe from PolicyModel pe inner join fetch pe.resources r inner join fetch pe.scopes s inner join fetch pe.associatedPolicies a where pe.resourceServer.id = :serverId and exists (select p.id from ScopeModel s inner join s.policies p where s.resourceServer.id = :serverId and (p.resourceServer.id = :serverId and p.type = 'scope' and s.id in (:scopeIds) and p.id = pe.id)) and exists (select p.id from ResourceModel r inner join r.policies p where r.resourceServer.id = :serverId and (p.resourceServer.id = :serverId and p.id = pe.id and p.type = 'scope' and r.id in (:resourceId)))")
    List<Policy> findPolicyIdByResourceScope(List<String> scopeIds, String resourceId, String resourceServerId);

    @Query(name = "findPolicyIdByNullResourceScope", value = "select pe from PolicyModel pe left join fetch pe.resources r inner join fetch pe.scopes s inner join fetch pe.associatedPolicies a where pe.resourceServer.id = :serverId and exists (select p.id from ScopeModel s inner join s.policies p where s.resourceServer.id = :serverId and (p.resourceServer.id = :serverId and p.id = pe.id and p.type = 'scope' and s.id in (:scopeIds))) and pe.resources is empty")
    List<Policy> findPolicyIdByNullResourceScope(List<String> scopeIds, String resourceServerId);

    @Query(name = "findPolicyIdByType", value = "select p.id from PolicyModel p where p.resourceServer.id = :serverId and p.type = :type")
    List<String> findPolicyIdByType(String serverId, String type);

    @Query(name = "findPolicyIdByResourceType", value = "select p from PolicyModel p inner join p.config c inner join fetch p.associatedPolicies a where p.resourceServer.id = :serverId and KEY(c) = 'defaultResourceType' and c like :type")
    List<Policy> findPolicyIdByResourceType(String type, String serverId);

    @Query(name = "findPolicyIdByDependentPolices", value = "select p.id from PolicyModel p inner join p.associatedPolicies ap where p.resourceServer.id = :serverId and (ap.resourceServer.id = :serverId and ap.id = :policyId)")
    List<String> findPolicyIdByDependentPolices(String serverId, String policyId);

    @Query(name = "deletePolicyByResourceServer", value = "delete from PolicyModel p where p.resourceServer.id = :serverId")
    void deletePolicyByResourceServer();
}
