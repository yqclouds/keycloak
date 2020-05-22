package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public interface ConditionalAuthenticator extends Authenticator {
    boolean matchCondition(AuthenticationFlowContext context);

    default void authenticate(AuthenticationFlowContext context) {
        // authenticate is not called for ConditionalAuthenticators
    }

    default boolean configuredFor(RealmModel realm, UserModel user) {
        return true;
    }
}
