package com.hsbc.unified.iam.facade.service;

import com.hsbc.unified.iam.entity.Realm;
import org.keycloak.models.RequiredCredentialModel;

import java.util.List;
import java.util.Set;

public interface RealmFacade {
    void addRequiredCredential(Realm realm, String type);

    void updateRequiredCredentials(Realm realm, Set<String> credentials);

    List<RequiredCredentialModel> getRequiredCredentials(Realm realm);

    List<String> getDefaultRoles(Realm realm);
}
