/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authorization.policy.evaluation;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.identity.Identity;
import com.hsbc.unified.iam.facade.model.authorization.PermissionTicketModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionTicketToken;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionTicketAwareDecisionResultCollector extends DecisionPermissionCollector {

    private final AuthorizationRequest request;
    private final Identity identity;
    private final AuthorizationProvider authorization;
    private PermissionTicketToken ticket;
    private ResourceServerModel resourceServer;

    public PermissionTicketAwareDecisionResultCollector(AuthorizationRequest request, PermissionTicketToken ticket, Identity identity, ResourceServerModel resourceServer, AuthorizationProvider authorization) {
        super(authorization, resourceServer, request);
        this.request = request;
        this.ticket = ticket;
        this.identity = identity;
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    @Override
    protected void onGrant(Permission grantedPermission) {
        // Removes permissions (represented by {@code ticket}) granted by any user-managed policy so we don't create unnecessary permission tickets.
        List<Permission> permissions = ticket.getPermissions();
        Iterator<Permission> itPermissions = permissions.iterator();

        while (itPermissions.hasNext()) {
            Permission permission = itPermissions.next();

            if (permission.getResourceId() == null || permission.getResourceId().equals(grantedPermission.getResourceId())) {
                Set<String> scopes = permission.getScopes();
                Iterator<String> itScopes = scopes.iterator();

                while (itScopes.hasNext()) {
                    if (grantedPermission.getScopes().contains(itScopes.next())) {
                        itScopes.remove();
                    }
                }

                if (scopes.isEmpty()) {
                    itPermissions.remove();
                }
            }
        }
    }

    @Override
    public void onComplete() {
        super.onComplete();

        if (request.isSubmitRequest()) {
            StoreFactory storeFactory = authorization.getStoreFactory();
            ResourceStore resourceStore = storeFactory.getResourceStore();
            List<Permission> permissions = ticket.getPermissions();

            if (permissions != null) {
                for (Permission permission : permissions) {
                    ResourceModel resource = resourceStore.findById(permission.getResourceId(), resourceServer.getId());

                    if (resource == null) {
                        resource = resourceStore.findByName(permission.getResourceId(), identity.getId(), resourceServer.getId());
                    }

                    if (resource == null || !resource.isOwnerManagedAccess() || resource.getOwner().equals(identity.getId()) || resource.getOwner().equals(resourceServer.getId())) {
                        continue;
                    }

                    Set<String> scopes = permission.getScopes();

                    if (scopes.isEmpty()) {
                        scopes = resource.getScopes().stream().map(ScopeModel::getName).collect(Collectors.toSet());
                    }

                    if (scopes.isEmpty()) {
                        Map<String, String> filters = new HashMap<>();

                        filters.put(PermissionTicketModel.RESOURCE, resource.getId());
                        filters.put(PermissionTicketModel.REQUESTER, identity.getId());
                        filters.put(PermissionTicketModel.SCOPE_IS_NULL, Boolean.TRUE.toString());

                        List<PermissionTicketModel> tickets = authorization.getStoreFactory().getPermissionTicketStore().find(filters, resource.getResourceServer().getId(), -1, -1);

                        if (tickets.isEmpty()) {
                            authorization.getStoreFactory().getPermissionTicketStore().create(resource.getId(), null, identity.getId(), resource.getResourceServer());
                        }
                    } else {
                        ScopeStore scopeStore = authorization.getStoreFactory().getScopeStore();

                        for (String scopeId : scopes) {
                            ScopeModel scope = scopeStore.findByName(scopeId, resourceServer.getId());

                            if (scope == null) {
                                scope = scopeStore.findById(scopeId, resourceServer.getId());
                            }

                            Map<String, String> filters = new HashMap<>();

                            filters.put(PermissionTicketModel.RESOURCE, resource.getId());
                            filters.put(PermissionTicketModel.REQUESTER, identity.getId());
                            filters.put(PermissionTicketModel.SCOPE, scope.getId());

                            List<PermissionTicketModel> tickets = authorization.getStoreFactory().getPermissionTicketStore().find(filters, resource.getResourceServer().getId(), -1, -1);

                            if (tickets.isEmpty()) {
                                authorization.getStoreFactory().getPermissionTicketStore().create(resource.getId(), scope.getId(), identity.getId(), resource.getResourceServer());
                            }
                        }
                    }
                }
            }
        }
    }
}
