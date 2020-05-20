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
package org.keycloak.authorization.protection.permission;

import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.model.PermissionTicketModel;
import org.keycloak.authorization.model.ResourceModel;
import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.authorization.model.ScopeModel;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import com.hsbc.unified.iam.core.constants.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionTicketService {

    private final AuthorizationProvider authorization;
    private final KeycloakIdentity identity;
    private final ResourceServerModel resourceServer;

    public PermissionTicketService(KeycloakIdentity identity, ResourceServerModel resourceServer, AuthorizationProvider authorization) {
        this.identity = identity;
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(PermissionTicketRepresentation representation) {
        PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();
        if (representation == null)
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "invalid_permission", Response.Status.BAD_REQUEST);
        if (representation.getId() != null)
            throw new ErrorResponseException("invalid_permission", "created permissions should not have id", Response.Status.BAD_REQUEST);
        if (representation.getResource() == null)
            throw new ErrorResponseException("invalid_permission", "created permissions should have resource", Response.Status.BAD_REQUEST);
        if (representation.getScope() == null && representation.getScopeName() == null)
            throw new ErrorResponseException("invalid_permission", "created permissions should have scope or scopeName", Response.Status.BAD_REQUEST);
        if (representation.getRequester() == null && representation.getRequesterName() == null)
            throw new ErrorResponseException("invalid_permission", "created permissions should have requester or requesterName", Response.Status.BAD_REQUEST);

        ResourceStore rstore = this.authorization.getStoreFactory().getResourceStore();
        ResourceModel resource = rstore.findById(representation.getResource(), resourceServer.getId());
        if (resource == null)
            throw new ErrorResponseException("invalid_resource_id", "ResourceModel set with id [" + representation.getResource() + "] does not exists in this server.", Response.Status.BAD_REQUEST);

        if (!resource.getOwner().equals(this.identity.getId()))
            throw new ErrorResponseException("not_authorised", "permissions for [" + representation.getResource() + "] can be only created by the owner", Response.Status.FORBIDDEN);

        UserModel user = null;
        if (representation.getRequester() != null)
            user = this.authorization.getSession().userStorageManager().getUserById(representation.getRequester(), this.authorization.getRealm());
        else
            user = this.authorization.getSession().userStorageManager().getUserByUsername(representation.getRequesterName(), this.authorization.getRealm());

        if (user == null)
            throw new ErrorResponseException("invalid_permission", "Requester does not exists in this server as user.", Response.Status.BAD_REQUEST);

        ScopeModel scope = null;
        ScopeStore sstore = this.authorization.getStoreFactory().getScopeStore();

        if (representation.getScopeName() != null)
            scope = sstore.findByName(representation.getScopeName(), resourceServer.getId());
        else
            scope = sstore.findById(representation.getScope(), resourceServer.getId());

        if (scope == null && representation.getScope() != null)
            throw new ErrorResponseException("invalid_scope", "ScopeModel [" + representation.getScope() + "] is invalid", Response.Status.BAD_REQUEST);
        if (scope == null && representation.getScopeName() != null)
            throw new ErrorResponseException("invalid_scope", "ScopeModel [" + representation.getScopeName() + "] is invalid", Response.Status.BAD_REQUEST);

        boolean match = resource.getScopes().contains(scope);

        if (!match)
            throw new ErrorResponseException("invalid_resource_id", "ResourceModel set with id [" + representation.getResource() + "] does not have ScopeModel [" + scope.getName() + "]", Response.Status.BAD_REQUEST);

        Map<String, String> attributes = new HashMap<>();
        attributes.put(PermissionTicketModel.RESOURCE, resource.getId());
        attributes.put(PermissionTicketModel.SCOPE, scope.getId());
        attributes.put(PermissionTicketModel.REQUESTER, user.getId());

        if (!ticketStore.find(attributes, resourceServer.getId(), -1, -1).isEmpty())
            throw new ErrorResponseException("invalid_permission", "Permission already exists", Response.Status.BAD_REQUEST);

        PermissionTicketModel ticket = ticketStore.create(resource.getId(), scope.getId(), user.getId(), resourceServer);
        if (representation.isGranted())
            ticket.setGrantedTimestamp(java.lang.System.currentTimeMillis());
        representation = ModelToRepresentation.toRepresentation(ticket, authorization);
        return Response.ok(representation).build();
    }

    @PUT
    @Consumes("application/json")
    public Response update(PermissionTicketRepresentation representation) {
        if (representation == null || representation.getId() == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "invalid_ticket", Response.Status.BAD_REQUEST);
        }

        PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();
        PermissionTicketModel ticket = ticketStore.findById(representation.getId(), resourceServer.getId());

        if (ticket == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "invalid_ticket", Response.Status.BAD_REQUEST);
        }

        if (!ticket.getOwner().equals(this.identity.getId()) && !this.identity.isResourceServer())
            throw new ErrorResponseException("not_authorised", "permissions for [" + representation.getResource() + "] can be updated only by the owner or by the resource server", Response.Status.FORBIDDEN);

        RepresentationToModel.toModel(representation, resourceServer.getId(), authorization);

        return Response.noContent().build();
    }


    @Path("{id}")
    @DELETE
    @Consumes("application/json")
    public Response delete(@PathParam("id") String id) {
        if (id == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "invalid_ticket", Response.Status.BAD_REQUEST);
        }

        PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();
        PermissionTicketModel ticket = ticketStore.findById(id, resourceServer.getId());

        if (ticket == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "invalid_ticket", Response.Status.BAD_REQUEST);
        }

        if (!ticket.getOwner().equals(this.identity.getId()) && !this.identity.isResourceServer() && !ticket.getRequester().equals(this.identity.getId()))
            throw new ErrorResponseException("not_authorised", "permissions for [" + ticket.getResource() + "] can be deleted only by the owner, the requester, or the resource server", Response.Status.FORBIDDEN);

        ticketStore.delete(id);

        return Response.noContent().build();
    }

    @GET
    @Produces("application/json")
    public Response find(@QueryParam("scopeId") String scopeId,
                         @QueryParam("resourceId") String resourceId,
                         @QueryParam("owner") String owner,
                         @QueryParam("requester") String requester,
                         @QueryParam("granted") Boolean granted,
                         @QueryParam("returnNames") Boolean returnNames,
                         @QueryParam("first") Integer firstResult,
                         @QueryParam("max") Integer maxResult) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        PermissionTicketStore permissionTicketStore = storeFactory.getPermissionTicketStore();

        Map<String, String> filters = new HashMap<>();

        if (resourceId != null) {
            filters.put(PermissionTicketModel.RESOURCE, resourceId);
        }

        if (scopeId != null) {
            ScopeStore scopeStore = storeFactory.getScopeStore();
            ScopeModel scope = scopeStore.findById(scopeId, resourceServer.getId());

            if (scope == null) {
                scope = scopeStore.findByName(scopeId, resourceServer.getId());
            }

            filters.put(PermissionTicketModel.SCOPE, scope != null ? scope.getId() : scopeId);
        }

        if (owner != null) {
            filters.put(PermissionTicketModel.OWNER, getUserId(owner));
        }

        if (requester != null) {
            filters.put(PermissionTicketModel.REQUESTER, getUserId(requester));
        }

        if (granted != null) {
            filters.put(PermissionTicketModel.GRANTED, granted.toString());
        }

        return Response.ok().entity(permissionTicketStore.find(filters, resourceServer.getId(), firstResult != null ? firstResult : -1, maxResult != null ? maxResult : Constants.DEFAULT_MAX_RESULTS)
                .stream()
                .map(permissionTicket -> ModelToRepresentation.toRepresentation(permissionTicket, authorization, returnNames == null ? false : returnNames))
                .collect(Collectors.toList()))
                .build();
    }

    private String getUserId(String userIdOrName) {
        UserProvider userProvider = authorization.getSession().users();
        RealmModel realm = authorization.getRealm();
        UserModel userModel = userProvider.getUserById(userIdOrName, realm);

        if (userModel != null) {
            return userModel.getId();
        }

        userModel = userProvider.getUserByUsername(userIdOrName, realm);

        if (userModel != null) {
            return userModel.getId();
        }

        return userIdOrName;
    }
}
