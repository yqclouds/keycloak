package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.Client;
import com.hsbc.unified.iam.core.entity.ClientScopeClientMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClientScopeClientMappingRepository extends JpaRepository<ClientScopeClientMapping, ClientScopeClientMapping.Key>,
        JpaSpecificationExecutor<ClientScopeClientMapping> {
    @Query(name = "clientScopeClientMappingIdsByClient", value = "select m.clientScope.id from ClientScopeClientMapping m where m.client = :client and m.defaultScope = :defaultScope")
    List<String> clientScopeClientMappingIdsByClient(String client, String defaultScope);

    @Query(name = "deleteClientScopeClientMapping", value = "delete from ClientScopeClientMapping where client = :client and clientScope = :clientScope")
    void deleteClientScopeClientMapping(String client, String clientScope);

    @Query(name = "deleteClientScopeClientMappingByClient", value = "delete from ClientScopeClientMapping where client = :client")
    void deleteClientScopeClientMappingByClient(Client client);
}
