package com.hsbc.unified.iam.repository;

import com.hsbc.unified.iam.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, String>,
        JpaSpecificationExecutor<Credential> {
}
