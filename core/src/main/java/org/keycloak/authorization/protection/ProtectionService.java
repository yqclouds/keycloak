/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.protection;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.admin.ResourceSetService;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.protection.permission.PermissionService;
import org.keycloak.authorization.protection.permission.PermissionTicketService;
import org.keycloak.authorization.protection.policy.UserManagedPermissionService;
import org.keycloak.authorization.protection.resource.ResourceService;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.models.*;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response.Status;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ProtectionService {

    private final AuthorizationProvider authorization;
    @Context
    protected ClientConnection clientConnection;

    public ProtectionService(AuthorizationProvider authorization) {
        this.authorization = authorization;
    }

    @Path("/resource_set")
    public Object resource() {
        KeycloakIdentity identity = createIdentity(true);
        ResourceServerModel resourceServer = getResourceServer(identity);
        ResourceSetService resourceManager = new ResourceSetService(resourceServer, this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(resourceManager);

        ResourceService resource = new ResourceService(resourceServer, identity, resourceManager);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Autowired
    private UserProvider userProvider;

    private AdminEventBuilder createAdminEventBuilder(KeycloakIdentity identity, ResourceServerModel resourceServer) {
        RealmModel realm = authorization.getRealm();
        ClientModel client = realm.getClientById(resourceServer.getId());
        UserModel serviceAccount = userProvider.getServiceAccount(client);
        AdminEventBuilder adminEvent = new AdminEventBuilder(realm, new AdminAuth(realm, identity.getAccessToken(), serviceAccount, client), clientConnection);
        return adminEvent.realm(realm).authClient(client).authUser(serviceAccount);
    }

    @Path("/permission")
    public Object permission() {
        KeycloakIdentity identity = createIdentity(false);

        PermissionService resource = new PermissionService(identity, getResourceServer(identity), this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/permission/ticket")
    public Object ticket() {
        KeycloakIdentity identity = createIdentity(false);

        PermissionTicketService resource = new PermissionTicketService(identity, getResourceServer(identity), this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/uma-policy")
    public Object policy() {
        KeycloakIdentity identity = createIdentity(false);

        UserManagedPermissionService resource = new UserManagedPermissionService(identity, getResourceServer(identity), this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Autowired
    private KeycloakContext context;
    @Autowired
    private Tokens tokens;

    private KeycloakIdentity createIdentity(boolean checkProtectionScope) {
        KeycloakIdentity identity = new KeycloakIdentity(tokens.getAccessToken(), context.getRealm());
        ResourceServerModel resourceServer = getResourceServer(identity);
        RealmModel realm = context.getRealm();
        ClientModel client = realm.getClientById(resourceServer.getId());

        if (checkProtectionScope) {
            if (!identity.hasClientRole(client.getClientId(), "uma_protection")) {
                throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_protection scope.", Status.FORBIDDEN);
            }
        }

        return identity;
    }

    private ResourceServerModel getResourceServer(KeycloakIdentity identity) {
        String clientId = identity.getAccessToken().getIssuedFor();
        RealmModel realm = context.getRealm();
        ClientModel clientModel = realm.getClientByClientId(clientId);

        if (clientModel == null) {
            clientModel = realm.getClientById(clientId);

            if (clientModel == null) {
                throw new ErrorResponseException("invalid_clientId", "Client application with id [" + clientId + "] does not exist in realm [" + realm.getName() + "]", Status.BAD_REQUEST);
            }
        }

        ResourceServerModel resourceServer = this.authorization.getStoreFactory().getResourceServerStore().findById(clientModel.getId());

        if (resourceServer == null) {
            throw new ErrorResponseException("invalid_clientId", "Client application [" + clientModel.getClientId() + "] is not registered as a resource server.", Status.FORBIDDEN);
        }

        return resourceServer;
    }
}
