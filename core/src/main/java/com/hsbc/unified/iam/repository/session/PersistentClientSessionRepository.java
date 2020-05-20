package com.hsbc.unified.iam.repository.session;

import com.hsbc.unified.iam.entity.session.PersistentClientSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface PersistentClientSessionRepository extends JpaRepository<PersistentClientSession, String>,
        JpaSpecificationExecutor<PersistentClientSession> {
    @Query(name = "deleteClientSessionsByRealm", value = "delete from PersistentClientSession sess where sess.userSessionId IN (select u.userSessionId from PersistentUserSession u where u.realmId = :realmId)")
    void deleteClientSessionsByRealm(String realmId);

    @Query(name = "deleteClientSessionsByClient", value = "delete from PersistentClientSession sess where sess.clientId = :clientId")
    void deleteClientSessionsByClient(String clientId);

    @Query(name = "deleteClientSessionsByExternalClient", value = "delete from PersistentClientSession sess where sess.clientStorageProvider = :clientStorageProvider and sess.externalClientId = :externalClientId")
    void deleteClientSessionsByExternalClient(String clientStorageProvider, String externalClientId);

    @Query(name = "deleteClientSessionsByClientStorageProvider", value = "delete from PersistentClientSession sess where sess.clientStorageProvider = :clientStorageProvider")
    void deleteClientSessionsByClientStorageProvider();

    @Query(name = "deleteClientSessionsByUser", value = "delete from PersistentClientSession sess where sess.userSessionId IN (select u.userSessionId from PersistentUserSession u where u.userId = :userId)")
    void deleteClientSessionsByUser(String userId);

    @Query(name = "deleteClientSessionsByUserSession", value = "delete from PersistentClientSession sess where sess.userSessionId = :userSessionId and sess.offline = :offline")
    void deleteClientSessionsByUserSession(String userSessionId, String offline);

    @Query(name = "deleteExpiredClientSessions", value = "delete from PersistentClientSession sess where sess.userSessionId IN (select u.userSessionId from PersistentUserSession u where u.realmId = :realmId AND u.offline = :offline AND u.lastSessionRefresh < :lastSessionRefresh)")
    int deleteExpiredClientSessions(String realmId, int lastSessionRefresh, String offline);

    @Query(name = "findClientSessionsByUserSession", value = "select sess from PersistentClientSession sess where sess.userSessionId=:userSessionId and sess.offline = :offline")
    List<PersistentClientSession> findClientSessionsByUserSession(String userSessionId, String offline);

    @Query(name = "findClientSessionsByUserSessions", value = "select sess from PersistentClientSession sess where sess.offline = :offline and sess.userSessionId IN (:userSessionIds) order by sess.userSessionId")
    List<PersistentClientSession> findClientSessionsByUserSessions(Collection<String> userSessionIds, String offline);

    PersistentClientSession findByKey(String userSessionId, String clientId, String clientStorageProvider, String externalId, String offlineStr);
}
