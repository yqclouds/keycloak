package org.keycloak.adapters.springsecurity.authentication;

import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.HttpFacade;

import javax.servlet.http.HttpServletRequest;

/**
 * Creates {@link RequestAuthenticator}s.
 */
public interface RequestAuthenticatorFactory {
    /**
     * Creates new {@link RequestAuthenticator} instances on a per-request basis.
     */
    RequestAuthenticator createRequestAuthenticator(HttpFacade facade, HttpServletRequest request,
                                                    KeycloakDeployment deployment, AdapterTokenStore tokenStore, int sslRedirectPort);
}