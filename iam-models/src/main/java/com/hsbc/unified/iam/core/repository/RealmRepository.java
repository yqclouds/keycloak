package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RealmRepository extends JpaRepository<Realm, String>, JpaSpecificationExecutor<Realm> {
    @Query(name = "Realm.getRealmIdsWithProviderType", value = "select distinct c.realm.id from Component c where c.providerType = :providerType")
    List<String> getRealmIdsWithProviderType(@Param("providerType") String providerType);

    @Query(name = "Realm.getAllRealmIds", value = "select realm.id from Realm realm")
    List<String> getAllRealmIds();

    @Query(name = "Realm.getRealmIdByName", value = "select realm.id from Realm realm where realm.name = :name")
    List<String> getRealmIdByName(@Param("name") String name);
}
