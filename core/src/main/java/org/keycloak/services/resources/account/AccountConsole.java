package org.keycloak.services.resources.account;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Created by st on 29/03/17.
 */
public class AccountConsole {
    private final AppAuthManager authManager;
    private final RealmModel realm;
    private final ClientModel client;
    @Context
    protected KeycloakSession session;
    private Auth auth;

    public AccountConsole(RealmModel realm, ClientModel client) {
        this.realm = realm;
        this.client = client;
        this.authManager = new AppAuthManager();
    }

    public void init() {
        AuthenticationManager.AuthResult authResult = authManager.authenticateIdentityCookie(realm);
        if (authResult != null) {
            auth = new Auth(realm, authResult.getToken(), authResult.getUser(), client, authResult.getSession(), true);
        }
    }

    @GET
    @Path("index.html")
    public Response getIndexHtmlRedirect() {
        return Response.status(302).location(session.getContext().getUri().getRequestUriBuilder().path("../").build()).build();
    }
}
