package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, String>, JpaSpecificationExecutor<User> {
    @Query(name = "getAllUsersByRealm", value = "select u from User u where u.realmId = :realmId order by u.username")
    List<User> getAllUsersByRealm(String realmId);

    @Query(name = "getAllUsersByRealmExcludeServiceAccount", value = "select u from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) order by u.username")
    List<User> getAllUsersByRealmExcludeServiceAccount(String realmId);

    @Query(name = "searchForUser", value = "select u from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) and " +
            "( lower(u.username) like :search or lower(concat(coalesce(u.firstName, ''), ' ', coalesce(u.lastName, ''))) like :search or u.email like :search ) order by u.username")
    List<User> searchForUser(String realmId, String search);

    @Query(name = "searchForUserCount", value = "select count(u) from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) and " +
            "( lower(u.username) like :search or lower(concat(coalesce(u.firstName, ''), ' ', coalesce(u.lastName, ''))) like :search or u.email like :search )")
    Long searchForUserCount(String realmId, String search);

    @Query(name = "getRealmUserByUsername", value = "select u from User u where u.username = :username and u.realmId = :realmId")
    List<User> getRealmUserByUsername(String username, String realmId);

    @Query(name = "getRealmUserByEmail", value = "select u from User u where u.email = :email and u.realmId = :realmId")
    List<User> getRealmUserByEmail(String email, String realmId);

    @Query(name = "getRealmUserByLastName", value = "select u from User u where u.lastName = :lastName and u.realmId = :realmId")
    List<User> getRealmUserByLastName();

    @Query(name = "getRealmUserByFirstLastName", value = "select u from User u where u.firstName = :first and u.lastName = :last and u.realmId = :realmId")
    List<User> getRealmUserByFirstLastName();

    @Query(name = "getRealmUserByServiceAccount", value = "select u from User u where u.serviceAccountClientLink = :clientInternalId and u.realmId = :realmId")
    List<User> getRealmUserByServiceAccount(String realmId, String clientInternalId);

    @Query(name = "getRealmUserCount", value = "select count(u) from User u where u.realmId = :realmId")
    Integer getRealmUserCount(String realmId);

    @Query(name = "getRealmUserCountExcludeServiceAccount", value = "select count(u) from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null)")
    Integer getRealmUserCountExcludeServiceAccount(String realmId);

    @Query(name = "getRealmUsersByAttributeNameAndValue", value = "select u from User u join u.attributes attr " +
            "where u.realmId = :realmId and attr.name = :name and attr.value = :value")
    List<User> getRealmUsersByAttributeNameAndValue(String realmId, String name, String value);

    @Query(name = "deleteUsersByRealm", value = "delete from User u where u.realmId = :realmId")
    void deleteUsersByRealm(String realmId);

    @Query(name = "deleteUsersByRealmAndLink", value = "delete from User u where u.realmId = :realmId and u.federationLink=:link")
    void deleteUsersByRealmAndLink(String realmId, String link);

    @Query(name = "unlinkUsers", value = "update User u set u.federationLink = null where u.realmId = :realmId and u.federationLink=:link")
    void unlinkUsers(String realmId, String link);
}
