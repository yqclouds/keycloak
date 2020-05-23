package org.keycloak.services.resources.account;

import org.keycloak.models.PasswordCredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.springframework.beans.factory.annotation.Autowired;

public class PasswordUtil {
    private UserModel user;

    @Autowired
    private UserCredentialManager userCredentialManager;

    public PasswordUtil(UserModel user) {
        this.user = user;
    }

    public boolean isConfigured(RealmModel realm, UserModel user) {
        return userCredentialManager.isConfiguredFor(realm, user, PasswordCredentialModel.TYPE);
    }

    public void update() {
    }
}
