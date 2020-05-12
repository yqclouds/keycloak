package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.Realm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface RealmRepository extends JpaRepository<Realm, String>, JpaSpecificationExecutor<Realm> {
}
