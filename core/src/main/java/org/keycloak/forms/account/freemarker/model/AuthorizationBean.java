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

package org.keycloak.forms.account.freemarker.model;

import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.facade.model.authorization.PermissionTicketModel;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.services.util.ResolveRelative;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import javax.ws.rs.core.UriInfo;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthorizationBean {

    private final UserModel user;
    @Autowired
    private AuthorizationProvider authorizationProvider;
    private final UriInfo uriInfo;
    private ResourceBean resource;
    private List<ResourceBean> resources;
    private Collection<ResourceBean> userSharedResources;
    private Collection<ResourceBean> requestsWaitingPermission;
    private Collection<ResourceBean> resourcesWaitingOthersApproval;

    public AuthorizationBean(UserModel user, UriInfo uriInfo) {
        this.user = user;
        this.uriInfo = uriInfo;
    }

    @PostConstruct
    public void afterPropertiesSet() {
        List<String> pathParameters = uriInfo.getPathParameters().get("resource_id");

        if (pathParameters != null && !pathParameters.isEmpty()) {
            ResourceModel resource = authorizationProvider.getStoreFactory().getResourceStore().findById(pathParameters.get(0), null);

            if (resource != null && !resource.getOwner().equals(user.getId())) {
                throw new RuntimeException("User [" + user.getUsername() + "] can not access resource [" + resource.getId() + "]");
            }
        }
    }

    public Collection<ResourceBean> getResourcesWaitingOthersApproval() {
        if (resourcesWaitingOthersApproval == null) {
            HashMap<String, String> filters = new HashMap<>();

            filters.put(PermissionTicketModel.REQUESTER, user.getId());
            filters.put(PermissionTicketModel.GRANTED, Boolean.FALSE.toString());

            resourcesWaitingOthersApproval = toResourceRepresentation(findPermissions(filters));
        }

        return resourcesWaitingOthersApproval;
    }

    public Collection<ResourceBean> getResourcesWaitingApproval() {
        if (requestsWaitingPermission == null) {
            HashMap<String, String> filters = new HashMap<>();

            filters.put(PermissionTicketModel.OWNER, user.getId());
            filters.put(PermissionTicketModel.GRANTED, Boolean.FALSE.toString());

            requestsWaitingPermission = toResourceRepresentation(findPermissions(filters));
        }

        return requestsWaitingPermission;
    }

    public List<ResourceBean> getResources() {
        if (resources == null) {
            resources = authorizationProvider.getStoreFactory().getResourceStore().findByOwner(user.getId(), null).stream()
                    .filter(ResourceModel::isOwnerManagedAccess)
                    .map(ResourceBean::new)
                    .collect(Collectors.toList());
        }
        return resources;
    }

    public Collection<ResourceBean> getSharedResources() {
        if (userSharedResources == null) {
            HashMap<String, String> filters = new HashMap<>();

            filters.put(PermissionTicketModel.REQUESTER, user.getId());
            filters.put(PermissionTicketModel.GRANTED, Boolean.TRUE.toString());

            PermissionTicketStore ticketStore = authorizationProvider.getStoreFactory().getPermissionTicketStore();

            userSharedResources = toResourceRepresentation(ticketStore.find(filters, null, -1, -1));
        }
        return userSharedResources;
    }

    public ResourceBean getResource() {
        if (resource == null) {
            String resourceId = uriInfo.getPathParameters().getFirst("resource_id");

            if (resourceId != null) {
                resource = getResource(resourceId);
            }
        }

        return resource;
    }

    private ResourceBean getResource(String id) {
        return new ResourceBean(authorizationProvider.getStoreFactory().getResourceStore().findById(id, null));
    }

    private Collection<RequesterBean> toPermissionRepresentation(List<PermissionTicketModel> permissionRequests) {
        Map<String, RequesterBean> requests = new HashMap<>();

        for (PermissionTicketModel ticket : permissionRequests) {
            ResourceModel resource = ticket.getResource();

            if (!resource.isOwnerManagedAccess()) {
                continue;
            }

            requests.computeIfAbsent(ticket.getRequester(), resourceId -> new RequesterBean(ticket, authorizationProvider)).addScope(ticket);
        }

        return requests.values();
    }

    private Collection<ResourceBean> toResourceRepresentation(List<PermissionTicketModel> tickets) {
        Map<String, ResourceBean> requests = new HashMap<>();

        for (PermissionTicketModel ticket : tickets) {
            ResourceModel resource = ticket.getResource();

            if (!resource.isOwnerManagedAccess()) {
                continue;
            }

            requests.computeIfAbsent(resource.getId(), resourceId -> getResource(resourceId)).addPermission(ticket, authorizationProvider);
        }

        return requests.values();
    }

    private List<PermissionTicketModel> findPermissions(Map<String, String> filters) {
        return authorizationProvider.getStoreFactory().getPermissionTicketStore().find(filters, null, -1, -1);
    }

    public static class RequesterBean {

        private final Long createdTimestamp;
        private final Long grantedTimestamp;
        private UserModel requester;
        private List<PermissionScopeBean> scopes = new ArrayList<>();
        private boolean granted;

        @Autowired
        private UserProvider userProvider;

        public RequesterBean(PermissionTicketModel ticket, AuthorizationProvider authorization) {
            this.requester = userProvider.getUserById(ticket.getRequester(), authorization.getRealm());
            granted = ticket.isGranted();
            createdTimestamp = ticket.getCreatedTimestamp();
            grantedTimestamp = ticket.getGrantedTimestamp();
        }

        public UserModel getRequester() {
            return requester;
        }

        public List<PermissionScopeBean> getScopes() {
            return scopes;
        }

        private void addScope(PermissionTicketModel ticket) {
            if (ticket != null) {
                scopes.add(new PermissionScopeBean(ticket));
            }
        }

        public boolean isGranted() {
            return (granted && scopes.isEmpty()) || scopes.stream().filter(permissionScopeBean -> permissionScopeBean.isGranted()).count() > 0;
        }

        public Date getCreatedDate() {
            return Time.toDate(createdTimestamp);
        }

        public Date getGrantedDate() {
            if (grantedTimestamp == null) {
                PermissionScopeBean permission = scopes.stream().filter(permissionScopeBean -> permissionScopeBean.isGranted()).findFirst().orElse(null);

                if (permission == null) {
                    return null;
                }

                return permission.getGrantedDate();
            }
            return Time.toDate(grantedTimestamp);
        }
    }

    public static class PermissionScopeBean {

        private final ScopeModel scope;
        private final PermissionTicketModel ticket;

        public PermissionScopeBean(PermissionTicketModel ticket) {
            this.ticket = ticket;
            scope = ticket.getScope();
        }

        public String getId() {
            return ticket.getId();
        }

        public ScopeModel getScope() {
            return scope;
        }

        public boolean isGranted() {
            return ticket.isGranted();
        }

        private Date getGrantedDate() {
            if (isGranted()) {
                return Time.toDate(ticket.getGrantedTimestamp());
            }
            return null;
        }
    }

    public class ResourceBean {

        private final ResourceServerBean resourceServer;
        private final UserModel owner;
        private ResourceModel resource;
        private Map<String, RequesterBean> permissions = new HashMap<>();
        private Collection<RequesterBean> shares;

        @Autowired
        private UserProvider userProvider;

        public ResourceBean(ResourceModel resource) {
            RealmModel realm = authorizationProvider.getRealm();
            resourceServer = new ResourceServerBean(realm.getClientById(resource.getResourceServer().getId()));
            this.resource = resource;
            owner = userProvider.getUserById(resource.getOwner(), realm);
        }

        public String getId() {
            return resource.getId();
        }

        public String getName() {
            return resource.getName();
        }

        public String getDisplayName() {
            return resource.getDisplayName();
        }

        public String getIconUri() {
            return resource.getIconUri();
        }

        public UserModel getOwner() {
            return owner;
        }

        public List<ScopeRepresentation> getScopes() {
            return resource.getScopes().stream().map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
        }

        public Collection<RequesterBean> getShares() {
            if (shares == null) {
                Map<String, String> filters = new HashMap<>();

                filters.put(PermissionTicketModel.RESOURCE, this.resource.getId());
                filters.put(PermissionTicketModel.GRANTED, Boolean.TRUE.toString());

                shares = toPermissionRepresentation(findPermissions(filters));
            }

            return shares;
        }

        public Collection<ManagedPermissionBean> getPolicies() {
            Map<String, String[]> filters = new HashMap<>();

            filters.put("type", new String[]{"uma"});
            filters.put("resource", new String[]{this.resource.getId()});
            filters.put("owner", new String[]{getOwner().getId()});

            List<PolicyModel> policies = authorizationProvider.getStoreFactory().getPolicyStore().findByResourceServer(filters, getResourceServer().getId(), -1, -1);

            if (policies.isEmpty()) {
                return Collections.emptyList();
            }

            return policies.stream()
                    .filter(policy -> {
                        Map<String, String> filters1 = new HashMap<>();

                        filters1.put(PermissionTicketModel.POLICY, policy.getId());

                        return authorizationProvider.getStoreFactory().getPermissionTicketStore().find(filters1, resourceServer.getId(), -1, 1)
                                .isEmpty();
                    })
                    .map(ManagedPermissionBean::new).collect(Collectors.toList());
        }

        public ResourceServerBean getResourceServer() {
            return resourceServer;
        }

        public Collection<RequesterBean> getPermissions() {
            return permissions.values();
        }

        private void addPermission(PermissionTicketModel ticket, AuthorizationProvider authorization) {
            permissions.computeIfAbsent(ticket.getRequester(), key -> new RequesterBean(ticket, authorization)).addScope(ticket);
        }
    }

    public class ResourceServerBean {

        private ClientModel clientModel;

        public ResourceServerBean(ClientModel clientModel) {
            this.clientModel = clientModel;
        }

        public String getId() {
            return clientModel.getId();
        }

        public String getName() {
            String name = clientModel.getName();

            if (name != null) {
                return name;
            }

            return clientModel.getClientId();
        }

        public String getClientId() {
            return clientModel.getClientId();
        }

        public String getRedirectUri() {
            Set<String> redirectUris = clientModel.getRedirectUris();

            if (redirectUris.isEmpty()) {
                return null;
            }

            return redirectUris.iterator().next();
        }

        public String getBaseUri() {
            return resolveRelative.resolveRelativeUri(clientModel.getRootUrl(), clientModel.getBaseUrl());
        }
    }

    @Autowired
    private ResolveRelative resolveRelative;

    public class ManagedPermissionBean {

        private final PolicyModel policy;
        private List<ManagedPermissionBean> policies;

        public ManagedPermissionBean(PolicyModel policy) {
            this.policy = policy;
        }

        public String getId() {
            return policy.getId();
        }

        public Collection<ScopeRepresentation> getScopes() {
            return policy.getScopes().stream().map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
        }

        public String getDescription() {
            return this.policy.getDescription();
        }

        public Collection<ManagedPermissionBean> getPolicies() {
            if (this.policies == null) {
                this.policies = policy.getAssociatedPolicies().stream().map(ManagedPermissionBean::new).collect(Collectors.toList());
            }

            return this.policies;
        }
    }
}
