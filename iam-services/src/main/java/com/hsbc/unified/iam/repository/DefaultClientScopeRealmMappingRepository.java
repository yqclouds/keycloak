package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.DefaultClientScopeRealmMapping;
import com.hsbc.unified.iam.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DefaultClientScopeRealmMappingRepository extends JpaRepository<DefaultClientScopeRealmMapping, DefaultClientScopeRealmMapping.Key>,
        JpaSpecificationExecutor<DefaultClientScopeRealmMapping> {
    @Query(name = "defaultClientScopeRealmMappingIdsByRealm", value = "select m.clientScope.id from DefaultClientScopeRealmMapping m where m.realm = :realm and m.defaultScope = :defaultScope")
    List<String> defaultClientScopeRealmMappingIdsByRealm();

    @Modifying
    @Query(name = "deleteDefaultClientScopeRealmMapping", value = "delete from DefaultClientScopeRealmMapping where realm = :realm and clientScope = :clientScope")
    void deleteDefaultClientScopeRealmMapping();

    @Modifying
    @Query(name = "deleteDefaultClientScopeRealmMappingByRealm", value = "delete from DefaultClientScopeRealmMapping where realm = :realm")
    void deleteDefaultClientScopeRealmMappingByRealm(Realm realm);
}
