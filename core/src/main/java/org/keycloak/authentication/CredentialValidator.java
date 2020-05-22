package org.keycloak.authentication;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;

public interface CredentialValidator<T extends CredentialProvider> {
    T getCredentialProvider();

    List<CredentialModel> getCredentials(RealmModel realm, UserModel user);

    String getType();
}
