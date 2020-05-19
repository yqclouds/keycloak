package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.UserAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAttributeRepository extends JpaRepository<UserAttribute, String>,
        JpaSpecificationExecutor<UserAttribute> {
    @Query(name = "deleteUserAttributesByRealm", value = "delete from  UserAttribute attr where attr.user IN (select u from User u where u.realmId=:realmId)")
    void deleteUserAttributesByRealm(String realmId);

    @Query(name = "deleteUserAttributesByNameAndUser", value = "delete from  UserAttribute attr where attr.user.id = :userId and attr.name = :name")
    void deleteUserAttributesByNameAndUser(String userId, String name);

    @Query(name = "deleteUserAttributesByNameAndUserOtherThan", value = "delete from  UserAttribute attr where attr.user.id = :userId and attr.name = :name and attr.id <> :attrId")
    void deleteUserAttributesByNameAndUserOtherThan(String userId, String name, String attrId);

    @Query(name = "deleteUserAttributesByRealmAndLink", value = "delete from  UserAttribute attr where attr.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteUserAttributesByRealmAndLink(String realmId, String link);
}
