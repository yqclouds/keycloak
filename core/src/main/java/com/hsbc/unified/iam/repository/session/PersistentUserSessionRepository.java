package com.hsbc.unified.iam.repository.session;

import com.hsbc.unified.iam.entity.session.PersistentUserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.stream.Stream;

@Repository
public interface PersistentUserSessionRepository extends JpaRepository<PersistentUserSession, String>,
        JpaSpecificationExecutor<PersistentUserSession> {
    @Query(name = "deleteUserSessionsByRealm", value = "delete from PersistentUserSession sess where sess.realmId = :realmId")
    void deleteUserSessionsByRealm(String realmId);

    @Query(name = "deleteUserSessionsByUser", value = "delete from PersistentUserSession sess where sess.userId = :userId")
    void deleteUserSessionsByUser(String userId);

    @Query(name = "deleteExpiredUserSessions", value = "delete from PersistentUserSession sess where sess.realmId = :realmId AND sess.offline = :offline AND sess.lastSessionRefresh < :lastSessionRefresh")
    int deleteExpiredUserSessions(String realmId, int lastSessionRefresh, String offline);

    @Query(name = "updateUserSessionLastSessionRefresh", value = "update PersistentUserSession sess set lastSessionRefresh = :lastSessionRefresh where sess.realmId = :realmId" +
            " AND sess.offline = :offline AND sess.userSessionId IN (:userSessionIds)")
    int updateUserSessionLastSessionRefresh(String realmId, int lastSessionRefresh, String offline, Collection<String> userSessionIds);

    @Query(name = "findUserSessionsCount", value = "select count(sess) from PersistentUserSession sess where sess.offline = :offline")
    int findUserSessionsCount(String offline);

    @Query(name = "findUserSessions", value = "select sess from PersistentUserSession sess where sess.offline = :offline" +
            " AND (sess.createdOn > :lastCreatedOn OR (sess.createdOn = :lastCreatedOn AND sess.userSessionId > :lastSessionId))" +
            " order by sess.createdOn,sess.userSessionId")
    Stream<PersistentUserSession> findUserSessions(String offline, int lastCreatedOn, String lastSessionId);

    void deleteByUserSessionIdAndOffline(String userSessionId, String offlineStr);

    PersistentUserSession findByKey(String userSessionId, String offlineStr);
}
