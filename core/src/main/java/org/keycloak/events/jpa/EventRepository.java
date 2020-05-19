package org.keycloak.events.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface EventRepository extends JpaRepository<Event, String>, JpaSpecificationExecutor<Event> {
    void deleteByRealmId(String realmId);

    void deleteByRealmIdAndTimeLessThan(String realmId, long olderThan);
}
