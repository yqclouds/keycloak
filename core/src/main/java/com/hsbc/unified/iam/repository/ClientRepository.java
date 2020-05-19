package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.Client;
import com.hsbc.unified.iam.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClientRepository extends JpaRepository<Client, String>, JpaSpecificationExecutor<Client> {
    @Query(name = "getClientsByRealm", value = "select client from Client client where client.realm = :realm")
    List<Client> findClientsByRealm(Realm realm);

    @Query(name = "getClientById", value = "select client from Client client where client.id = :id and client.realm.id = :realm")
    Client getClientById(String id, String realm);

    @Query(name = "getClientIdsByRealm", value = "select client.id from Client client where client.realm.id = :realm order by client.clientId")
    List<String> getClientIdsByRealm(String realm);

    @Query(name = "getAlwaysDisplayInConsoleClients", value = "select client.id from Client client where client.alwaysDisplayInConsole = true and client.realm.id = :realm  order by client.clientId")
    List<String> getAlwaysDisplayInConsoleClients(String realm);

    @Query(name = "findClientIdByClientId", value = "select client.id from Client client where client.clientId = :clientId and client.realm.id = :realm")
    List<String> findClientIdByClientId(String clientId, String realm);

    @Query(name = "searchClientsByClientId", value = "select client.id from Client client where lower(client.clientId) like lower(concat('%',:clientId,'%')) and client.realm.id = :realm order by client.clientId")
    List<String> searchClientsByClientId(String clientId, String realm);

    @Query(name = "getRealmClientsCount", value = "select count(client) from Client client where client.realm.id = :realm")
    Long getRealmClientsCount(String realm);

    @Query(name = "findClientByClientId", value = "select client from Client client where client.clientId = :clientId and client.realm.id = :realm")
    List<Client> findClientByClientId(String clientId, String realm);
}
