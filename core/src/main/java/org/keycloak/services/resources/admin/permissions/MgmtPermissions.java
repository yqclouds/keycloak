/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.services.resources.admin.permissions;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.common.UserModelIdentity;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.models.*;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class MgmtPermissions implements AdminPermissionEvaluator, AdminPermissionManagement, RealmsPermissionEvaluator {
    protected RealmModel realm;
    @Autowired
    protected AuthorizationProvider authz;
    protected AdminAuth auth;
    protected Identity identity;
    protected UserModel admin;
    protected RealmModel adminsRealm;
    protected ResourceServerModel realmResourceServer;
    protected UserPermissions users;
    protected GroupPermissions groups;
    protected RealmPermissions realmPermissions;
    protected ClientPermissions clientPermissions;
    protected IdentityProviderPermissions idpPermissions;
    protected ScopeModel manageScope;
    protected ScopeModel viewScope;

    public MgmtPermissions(RealmModel realm) {
        this.realm = realm;
    }

    public MgmtPermissions(RealmModel realm, AdminAuth auth) {
        this(realm);
        this.auth = auth;
        this.admin = auth.getUser();
        this.adminsRealm = auth.getRealm();
        if (!auth.getRealm().equals(realm)
                && !auth.getRealm().equals(new RealmManager().getKeycloakAdministrationRealm())) {
            throw new ForbiddenException();
        }
        initIdentity(auth);
    }

    public MgmtPermissions(AdminAuth auth) {
        this.auth = auth;
        this.admin = auth.getUser();
        this.adminsRealm = auth.getRealm();
        initIdentity(auth);
    }

    public MgmtPermissions(RealmModel adminsRealm, UserModel admin) {
        this.admin = admin;
        this.adminsRealm = adminsRealm;
        this.identity = new UserModelIdentity(adminsRealm, admin);
    }

    MgmtPermissions(RealmModel realm, RealmModel adminsRealm, UserModel admin) {
        this(realm);
        this.admin = admin;
        this.adminsRealm = adminsRealm;
        this.identity = new UserModelIdentity(realm, admin);
    }

    private void initIdentity(AdminAuth auth) {
        if (Constants.ADMIN_CLI_CLIENT_ID.equals(auth.getToken().getIssuedFor())
                || Constants.ADMIN_CONSOLE_CLIENT_ID.equals(auth.getToken().getIssuedFor())) {
            this.identity = new UserModelIdentity(auth.getRealm(), auth.getUser());
        } else {
            this.identity = new KeycloakIdentity(auth.getToken());
        }
    }

    @Override
    public ClientModel getRealmManagementClient() {
        ClientModel client = null;
        if (realm.getName().equals(Config.getAdminRealm())) {
            client = realm.getClientByClientId(Config.getAdminRealm() + "-realm");
        } else {
            client = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        }
        return client;
    }

    @Override
    public AuthorizationProvider authz() {
        return authz;
    }

    @Override
    public void requireAnyAdminRole() {
        if (!hasAnyAdminRole()) {
            throw new ForbiddenException();
        }
    }

    public boolean hasAnyAdminRole() {
        return hasOneAdminRole(AdminRoles.ALL_REALM_ROLES);
    }

    public boolean hasAnyAdminRole(RealmModel realm) {
        return hasOneAdminRole(realm, AdminRoles.ALL_REALM_ROLES);
    }

    public boolean hasOneAdminRole(String... adminRoles) {
        String clientId;
        RealmModel realm = this.realm;
        return hasOneAdminRole(realm, adminRoles);
    }

    public boolean hasOneAdminRole(RealmModel realm, String... adminRoles) {
        String clientId;
        RealmManager realmManager = new RealmManager();
        if (adminsRealm.equals(realmManager.getKeycloakAdministrationRealm())) {
            clientId = realm.getMasterAdminClient().getClientId();
        } else if (adminsRealm.equals(realm)) {
            clientId = realm.getClientByClientId(realmManager.getRealmAdminClientId(realm)).getClientId();
        } else {
            return false;
        }
        for (String adminRole : adminRoles) {
            if (identity.hasClientRole(clientId, adminRole)) return true;
        }
        return false;
    }

    public boolean isAdminSameRealm() {
        return auth == null || realm.getId().equals(auth.getRealm().getId());
    }

    @Override
    public AdminAuth adminAuth() {
        return auth;
    }

    public Identity identity() {
        return identity;
    }

    public UserModel admin() {
        return admin;
    }

    public RealmModel adminsRealm() {
        return adminsRealm;
    }

    @Override
    public RolePermissions roles() {
        return new RolePermissions(realm, authz, this);
    }

    @Override
    public UserPermissions users() {
        if (users != null) return users;
        users = new UserPermissions(authz, this);
        return users;
    }

    @Override
    public RealmPermissions realm() {
        if (realmPermissions != null) return realmPermissions;
        realmPermissions = new RealmPermissions(realm, authz, this);
        return realmPermissions;
    }

    @Override
    public ClientPermissions clients() {
        if (clientPermissions != null) return clientPermissions;
        clientPermissions = new ClientPermissions(realm, authz, this);
        return clientPermissions;
    }

    @Override
    public IdentityProviderPermissions idps() {
        if (idpPermissions != null) return idpPermissions;
        idpPermissions = new IdentityProviderPermissions(realm, authz, this);
        return idpPermissions;
    }

    @Override
    public GroupPermissions groups() {
        if (groups != null) return groups;
        groups = new GroupPermissions(authz, this);
        return groups;
    }

    public ResourceServerModel findOrCreateResourceServer(ClientModel client) {
        return initializeRealmResourceServer();
    }

    public ResourceServerModel resourceServer(ClientModel client) {
        return realmResourceServer();
    }

    @Override
    public ResourceServerModel realmResourceServer() {
        if (realmResourceServer != null) return realmResourceServer;
        ClientModel client = getRealmManagementClient();
        if (client == null) return null;
        ResourceServerStore resourceServerStore = authz.getStoreFactory().getResourceServerStore();
        realmResourceServer = resourceServerStore.findById(client.getId());
        return realmResourceServer;

    }

    public ResourceServerModel initializeRealmResourceServer() {
        if (realmResourceServer != null) return realmResourceServer;
        ClientModel client = getRealmManagementClient();
        realmResourceServer = authz.getStoreFactory().getResourceServerStore().findById(client.getId());
        if (realmResourceServer == null) {
            realmResourceServer = authz.getStoreFactory().getResourceServerStore().create(client.getId());
        }
        return realmResourceServer;
    }

    public void initializeRealmDefaultScopes() {
        ResourceServerModel server = initializeRealmResourceServer();
        manageScope = initializeRealmScope(MgmtPermissions.MANAGE_SCOPE);
        viewScope = initializeRealmScope(MgmtPermissions.VIEW_SCOPE);
    }

    public ScopeModel initializeRealmScope(String name) {
        ResourceServerModel server = initializeRealmResourceServer();
        ScopeModel scope = authz.getStoreFactory().getScopeStore().findByName(name, server.getId());
        if (scope == null) {
            scope = authz.getStoreFactory().getScopeStore().create(name, server);
        }
        return scope;
    }

    public ScopeModel initializeScope(String name, ResourceServerModel server) {
        ScopeModel scope = authz.getStoreFactory().getScopeStore().findByName(name, server.getId());
        if (scope == null) {
            scope = authz.getStoreFactory().getScopeStore().create(name, server);
        }
        return scope;
    }


    public ScopeModel realmManageScope() {
        if (manageScope != null) return manageScope;
        manageScope = realmScope(MgmtPermissions.MANAGE_SCOPE);
        return manageScope;
    }


    public ScopeModel realmViewScope() {
        if (viewScope != null) return viewScope;
        viewScope = realmScope(MgmtPermissions.VIEW_SCOPE);
        return viewScope;
    }

    public ScopeModel realmScope(String scope) {
        ResourceServerModel server = realmResourceServer();
        if (server == null) return null;
        return authz.getStoreFactory().getScopeStore().findByName(scope, server.getId());
    }

    public boolean evaluatePermission(ResourceModel resource, ResourceServerModel resourceServer, ScopeModel... scope) {
        Identity identity = identity();
        if (identity == null) {
            throw new RuntimeException("Identity of admin is not set for permission query");
        }
        return evaluatePermission(resource, resourceServer, identity, scope);
    }

    public Collection<Permission> evaluatePermission(ResourcePermission permission, ResourceServerModel resourceServer) {
        return evaluatePermission(permission, resourceServer, new DefaultEvaluationContext(identity));
    }

    public Collection<Permission> evaluatePermission(ResourcePermission permission, ResourceServerModel resourceServer, EvaluationContext context) {
        return evaluatePermission(Arrays.asList(permission), resourceServer, context);
    }

    public boolean evaluatePermission(ResourceModel resource, ResourceServerModel resourceServer, Identity identity, ScopeModel... scope) {
        EvaluationContext context = new DefaultEvaluationContext(identity);
        return evaluatePermission(resource, resourceServer, context, scope);
    }

    public boolean evaluatePermission(ResourceModel resource, ResourceServerModel resourceServer, EvaluationContext context, ScopeModel... scope) {
        return !evaluatePermission(Arrays.asList(new ResourcePermission(resource, Arrays.asList(scope), resourceServer)), resourceServer, context).isEmpty();
    }

    @Autowired
    private KeycloakContext keycloakContext;

    public Collection<Permission> evaluatePermission(List<ResourcePermission> permissions, ResourceServerModel resourceServer, EvaluationContext context) {
        RealmModel oldRealm = keycloakContext.getRealm();
        try {
            keycloakContext.setRealm(realm);
            return authz.evaluators().from(permissions, context).evaluate(resourceServer, null);
        } finally {
            keycloakContext.setRealm(oldRealm);
        }
    }

    @Override
    public boolean canView(RealmModel realm) {
        return hasOneAdminRole(realm, AdminRoles.VIEW_REALM, AdminRoles.MANAGE_REALM);
    }

    @Override
    public boolean isAdmin(RealmModel realm) {
        return hasAnyAdminRole(realm);
    }

    @Autowired
    private RealmProvider realmProvider;

    @Override
    public boolean isAdmin() {
        RealmManager realmManager = new RealmManager();
        if (adminsRealm.equals(realmManager.getKeycloakAdministrationRealm())) {
            if (identity.hasRealmRole(AdminRoles.ADMIN) || identity.hasRealmRole(AdminRoles.CREATE_REALM)) {
                return true;
            }
            for (RealmModel realm : realmProvider.getRealms()) {
                if (isAdmin(realm)) return true;
            }
            return false;
        } else {
            return isAdmin(adminsRealm);
        }
    }

    @Override
    public boolean canCreateRealm() {
        RealmManager realmManager = new RealmManager();
        if (!auth.getRealm().equals(realmManager.getKeycloakAdministrationRealm())) {
            return false;
        }
        return identity.hasRealmRole(AdminRoles.CREATE_REALM);
    }

    @Override
    public void requireCreateRealm() {
        if (!canCreateRealm()) {
            throw new ForbiddenException();
        }
    }


}
