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
package org.keycloak.authorization.protection.permission;

import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.TokenManager;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionResponse;
import org.keycloak.representations.idm.authorization.PermissionTicketToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.Urls;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AbstractPermissionService {

    private final AuthorizationProvider authorization;
    private final KeycloakIdentity identity;
    private final ResourceServerModel resourceServer;

    public AbstractPermissionService(KeycloakIdentity identity, ResourceServerModel resourceServer, AuthorizationProvider authorization) {
        this.identity = identity;
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    public Response create(List<PermissionRequest> request) {
        if (request == null || request.isEmpty()) {
            throw new ErrorResponseException("invalid_permission_request", "Invalid permission request.", Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.CREATED).entity(new PermissionResponse(createPermissionTicket(request))).build();
    }

    private List<Permission> verifyRequestedResource(List<PermissionRequest> request) {
        ResourceStore resourceStore = authorization.getStoreFactory().getResourceStore();
        List<Permission> requestedResources = new ArrayList<>();

        for (PermissionRequest permissionRequest : request) {
            String resourceSetId = permissionRequest.getResourceId();
            List<ResourceModel> resources = new ArrayList<>();

            if (resourceSetId == null) {
                if (permissionRequest.getScopes() == null || permissionRequest.getScopes().isEmpty()) {
                    throw new ErrorResponseException("invalid_resource_id", "ResourceModel id or name not provided.", Response.Status.BAD_REQUEST);
                }
            } else {
                ResourceModel resource = resourceStore.findById(resourceSetId, resourceServer.getId());

                if (resource != null) {
                    resources.add(resource);
                } else {
                    ResourceModel userResource = resourceStore.findByName(resourceSetId, identity.getId(), this.resourceServer.getId());

                    if (userResource != null) {
                        resources.add(userResource);
                    }

                    if (!identity.isResourceServer()) {
                        ResourceModel serverResource = resourceStore.findByName(resourceSetId, this.resourceServer.getId());

                        if (serverResource != null) {
                            resources.add(serverResource);
                        }
                    }
                }

                if (resources.isEmpty()) {
                    throw new ErrorResponseException("invalid_resource_id", "ResourceModel set with id [" + resourceSetId + "] does not exists in this server.", Response.Status.BAD_REQUEST);
                }
            }

            if (resources.isEmpty()) {
                requestedResources.add(new Permission(null, verifyRequestedScopes(permissionRequest, null)));
            } else {
                for (ResourceModel resource : resources) {
                    requestedResources.add(new Permission(resource.getId(), verifyRequestedScopes(permissionRequest, resource)));
                }
            }
        }

        return requestedResources;
    }

    private Set<String> verifyRequestedScopes(PermissionRequest request, ResourceModel resource) {
        Set<String> requestScopes = request.getScopes();

        if (requestScopes == null) {
            return Collections.emptySet();
        }

        ResourceStore resourceStore = authorization.getStoreFactory().getResourceStore();

        return requestScopes.stream().map(scopeName -> {
            ScopeModel scope;

            if (resource != null) {
                scope = resource.getScopes().stream().filter(scope1 -> scope1.getName().equals(scopeName)).findFirst().orElse(null);

                if (scope == null && resource.getType() != null) {
                    scope = resourceStore.findByType(resource.getType(), resourceServer.getId()).stream()
                            .filter(baseResource -> baseResource.getOwner().equals(resource.getResourceServer().getId()))
                            .flatMap(resource1 -> resource1.getScopes().stream())
                            .filter(baseScope -> baseScope.getName().equals(scopeName)).findFirst().orElse(null);
                }
            } else {
                scope = authorization.getStoreFactory().getScopeStore().findByName(scopeName, resourceServer.getId());
            }

            if (scope == null) {
                throw new ErrorResponseException("invalid_scope", "ScopeModel [" + scopeName + "] is invalid", Response.Status.BAD_REQUEST);
            }

            return scope.getName();
        }).collect(Collectors.toSet());
    }

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private TokenManager tokenManager;

    private String createPermissionTicket(List<PermissionRequest> request) {
        List<Permission> permissions = verifyRequestedResource(request);

        String audience = Urls.realmIssuer(keycloakContext.getUri().getBaseUri(), this.authorization.getRealm().getName());
        PermissionTicketToken token = new PermissionTicketToken(permissions, audience, this.identity.getAccessToken());
        Map<String, List<String>> claims = new HashMap<>();

        for (PermissionRequest permissionRequest : request) {
            Map<String, List<String>> requestClaims = permissionRequest.getClaims();

            if (requestClaims != null) {
                claims.putAll(requestClaims);
            }
        }

        if (!claims.isEmpty()) {
            token.setClaims(claims);
        }

        return tokenManager.encode(token);
    }
}