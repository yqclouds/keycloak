package com.hsbc.unified.iam.repository.storage;

import com.hsbc.unified.iam.entity.storage.FederatedUserRequiredAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FederatedUserRequiredActionRepository extends JpaRepository<FederatedUserRequiredAction, FederatedUserRequiredAction.Key>,
        JpaSpecificationExecutor<FederatedUserRequiredAction> {
    @Query(name = "getFederatedUserRequiredActionsByUser", value = "select action from FederatedUserRequiredAction action where action.userId = :userId and action.realmId=:realmId")
    List<FederatedUserRequiredAction> getFederatedUserRequiredActionsByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUserRequiredActionsByUser", value = "delete from FederatedUserRequiredAction action where action.realmId=:realmId and action.userId = :userId")
    void deleteFederatedUserRequiredActionsByUser(String userId, String realmId);

    @Query(name = "deleteFederatedUserRequiredActionsByRealm", value = "delete from FederatedUserRequiredAction action where action.realmId=:realmId")
    void deleteFederatedUserRequiredActionsByRealm(String realmId);

    @Query(name = "deleteFederatedUserRequiredActionsByStorageProvider", value = "delete from FederatedUserRequiredAction e where e.storageProviderId=:storageProviderId")
    void deleteFederatedUserRequiredActionsByStorageProvider(String storageProviderId);

    @Query(name = "deleteFederatedUserRequiredActionsByRealmAndLink", value = "delete from FederatedUserRequiredAction action where action.userId IN (select u.id from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteFederatedUserRequiredActionsByRealmAndLink();
}
