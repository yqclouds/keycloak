package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.UserRequiredAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.persistence.NamedQuery;

@Repository
public interface UserRequiredActionRepository extends JpaRepository<UserRequiredAction, UserRequiredAction.Key>,
        JpaSpecificationExecutor<UserRequiredAction> {
    @Query(name = "deleteUserRequiredActionsByRealm", value = "delete from UserRequiredAction action where action.user IN (select u from User u where u.realmId=:realmId)")
    void deleteUserRequiredActionsByRealm(String realmId);
    @Query(name = "deleteUserRequiredActionsByRealmAndLink", value = "delete from UserRequiredAction action where action.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteUserRequiredActionsByRealmAndLink(String realmId, String link);
}
