package org.keycloak.storage.jpa.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BrokerLinkRepository extends JpaRepository<BrokerLink, BrokerLink.Key>, JpaSpecificationExecutor<BrokerLink> {
    @Query(name = "findBrokerLinkByUser", value = "select link from BrokerLink link where link.userId = :userId")
    List<BrokerLink> findBrokerLinkByUser(String userId);

    @Query(name = "findBrokerLinkByUserAndProvider", value = "select link from BrokerLink link where link.userId = :userId and link.identityProvider = :identityProvider and link.realmId = :realmId")
    List<BrokerLink> findBrokerLinkByUserAndProvider(String realmId, String userId, String identityProvider);

    @Query(name = "findUserByBrokerLinkAndRealm", value = "select link.userId from BrokerLink link where link.realmId = :realmId and link.identityProvider = :identityProvider and link.brokerUserId = :brokerUserId")
    List<String> findUserByBrokerLinkAndRealm(String realmId, String identityProvider, String brokerUserId);

    @Query(name = "deleteBrokerLinkByStorageProvider", value = "delete from BrokerLink social where social.storageProviderId = :storageProviderId")
    int deleteBrokerLinkByStorageProvider(String storageProviderId);

    @Query(name = "deleteBrokerLinkByRealm", value = "delete from BrokerLink social where social.realmId = :realmId")
    int deleteBrokerLinkByRealm(String realmId);

    @Query(name = "deleteBrokerLinkByRealmAndLink", value = "delete from BrokerLink social where social.userId IN (select u.id from User u where realmId=:realmId and u.federationLink=:link)")
    int deleteBrokerLinkByRealmAndLink();

    @Query(name = "deleteBrokerLinkByUser", value = "delete from BrokerLink social where social.userId = :userId and social.realmId = :realmId")
    int deleteBrokerLinkByUser(String userId, String realmId);
}
