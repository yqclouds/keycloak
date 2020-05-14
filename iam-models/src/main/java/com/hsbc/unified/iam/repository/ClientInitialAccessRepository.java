package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.ClientInitialAccess;
import com.hsbc.unified.iam.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClientInitialAccessRepository extends JpaRepository<ClientInitialAccess, String>,
        JpaSpecificationExecutor<ClientInitialAccess> {
    @Query(name = "findClientInitialAccessByRealm", value = "select ia from ClientInitialAccess ia where ia.realm = :realm order by timestamp")
    List<ClientInitialAccess> findClientInitialAccessByRealm(Realm realm);

    @Modifying
    @Query(name = "removeClientInitialAccessByRealm", value = "delete from ClientInitialAccess ia where ia.realm = :realm")
    void removeClientInitialAccessByRealm(Realm realm);

    @Modifying
    @Query(name = "removeExpiredClientInitialAccess", value = "delete from ClientInitialAccess ia where (ia.expiration > 0 and (ia.timestamp + ia.expiration) < :currentTime) or ia.remainingCount = 0")
    void removeExpiredClientInitialAccess(int currentTime);

    @Modifying
    @Query(name = "decreaseClientInitialAccessRemainingCount", value = "update ClientInitialAccess ia set ia.remainingCount = ia.remainingCount - 1 where ia.id = :id")
    void decreaseClientInitialAccessRemainingCount(String id);
}
