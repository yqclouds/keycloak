package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.Credential;
import com.hsbc.unified.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, String>,
        JpaSpecificationExecutor<Credential> {
    @Query(name = "credentialByUser", value = "select cred from Credential cred where cred.user = :user order by cred.priority")
    List<Credential> credentialByUser(User user);

    @Query(name = "deleteCredentialsByRealm", value = "delete from Credential cred where cred.user IN (select u from User u where u.realmId=:realmId)")
    void deleteCredentialsByRealm(String realmId);

    @Query(name = "deleteCredentialsByRealmAndLink", value = "delete from Credential cred where cred.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)")
    void deleteCredentialsByRealmAndLink(String realmId, String link);
}
