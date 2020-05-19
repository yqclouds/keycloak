package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.FederatedIdentity;
import com.hsbc.unified.iam.entity.IdentityProvider;
import com.hsbc.unified.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentity, FederatedIdentity.Key>,
        JpaSpecificationExecutor<FederatedIdentity> {
    @Query(name = "findFederatedIdentityByUser", value = "select link from FederatedIdentity link where link.user = :user")
    List<FederatedIdentity> findFederatedIdentityByUser(User user);

    @Query(name = "findFederatedIdentityByUserAndProvider", value = "select link from FederatedIdentity link where link.user = :user and link.identityProvider = :identityProvider")
    List<FederatedIdentity> findFederatedIdentityByUserAndProvider(User user, String identityProvider);

    @Query(name = "findUserByFederatedIdentityAndRealm", value = "select link.user from FederatedIdentity link where link.realmId = :realmId and link.identityProvider = :identityProvider and link.userId = :userId")
    List<User> findUserByFederatedIdentityAndRealm(String realmId, String userId, String identityProvider);

    @Query(name = "deleteFederatedIdentityByRealm", value = "delete from FederatedIdentity social where social.user IN (select u from User u where realmId=:realmId)")
    void deleteFederatedIdentityByRealm(String realmId);

    @Query(name = "deleteFederatedIdentityByRealmAndLink", value = "delete from FederatedIdentity social where social.user IN (select u from User u where realmId=:realmId and u.federationLink=:link)")
    void deleteFederatedIdentityByRealmAndLink(String realmId, String link);

    @Query(name = "deleteFederatedIdentityByUser", value = "delete from FederatedIdentity social where social.user = :user")
    void deleteFederatedIdentityByUser(User user);
}
