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

import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.ClientModelIdentity;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.UserModelIdentity;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.*;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ForbiddenException;

import java.util.*;
import java.util.function.Predicate;

/**
 * Manages default policies for all users.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class UserPermissions implements UserPermissionEvaluator, UserPermissionManagement {

    private static final String MAP_ROLES_SCOPE = "map-roles";
    private static final String IMPERSONATE_SCOPE = "impersonate";
    private static final String USER_IMPERSONATED_SCOPE = "user-impersonated";
    private static final String MANAGE_GROUP_MEMBERSHIP_SCOPE = "manage-group-membership";
    private static final String MAP_ROLES_PERMISSION_USERS = "map-roles.permission.users";
    private static final String ADMIN_IMPERSONATING_PERMISSION = "admin-impersonating.permission.users";
    private static final String USER_IMPERSONATED_PERMISSION = "user-impersonated.permission.users";
    private static final String MANAGE_GROUP_MEMBERSHIP_PERMISSION_USERS = "manage-group-membership.permission.users";
    private static final String MANAGE_PERMISSION_USERS = "manage.permission.users";
    private static final String VIEW_PERMISSION_USERS = "view.permission.users";
    private static final String USERS_RESOURCE = "Users";

    private final AuthorizationProvider authz;
    private final MgmtPermissions root;
    private final PolicyStore policyStore;
    private final ResourceStore resourceStore;
    private boolean grantIfNoPermission = false;

    UserPermissions(AuthorizationProvider authz, MgmtPermissions root) {
        this.authz = authz;
        this.root = root;
        policyStore = authz.getStoreFactory().getPolicyStore();
        resourceStore = authz.getStoreFactory().getResourceStore();
    }


    private void initialize() {
        root.initializeRealmResourceServer();
        root.initializeRealmDefaultScopes();
        ResourceServerModel server = root.realmResourceServer();
        ScopeModel manageScope = root.realmManageScope();
        ScopeModel viewScope = root.realmViewScope();
        ScopeModel mapRolesScope = root.initializeRealmScope(MAP_ROLES_SCOPE);
        ScopeModel impersonateScope = root.initializeRealmScope(IMPERSONATE_SCOPE);
        ScopeModel userImpersonatedScope = root.initializeRealmScope(USER_IMPERSONATED_SCOPE);
        ScopeModel manageGroupMembershipScope = root.initializeRealmScope(MANAGE_GROUP_MEMBERSHIP_SCOPE);

        ResourceModel usersResource = resourceStore.findByName(USERS_RESOURCE, server.getId());
        if (usersResource == null) {
            usersResource = resourceStore.create(USERS_RESOURCE, server, server.getId());
            Set<ScopeModel> scopeset = new HashSet<>();
            scopeset.add(manageScope);
            scopeset.add(viewScope);
            scopeset.add(mapRolesScope);
            scopeset.add(impersonateScope);
            scopeset.add(manageGroupMembershipScope);
            scopeset.add(userImpersonatedScope);
            usersResource.updateScopes(scopeset);
        }
        PolicyModel managePermission = policyStore.findByName(MANAGE_PERMISSION_USERS, server.getId());
        if (managePermission == null) {
            Helper.addEmptyScopePermission(authz, server, MANAGE_PERMISSION_USERS, usersResource, manageScope);
        }
        PolicyModel viewPermission = policyStore.findByName(VIEW_PERMISSION_USERS, server.getId());
        if (viewPermission == null) {
            Helper.addEmptyScopePermission(authz, server, VIEW_PERMISSION_USERS, usersResource, viewScope);
        }
        PolicyModel mapRolesPermission = policyStore.findByName(MAP_ROLES_PERMISSION_USERS, server.getId());
        if (mapRolesPermission == null) {
            Helper.addEmptyScopePermission(authz, server, MAP_ROLES_PERMISSION_USERS, usersResource, mapRolesScope);
        }
        PolicyModel membershipPermission = policyStore.findByName(MANAGE_GROUP_MEMBERSHIP_PERMISSION_USERS, server.getId());
        if (membershipPermission == null) {
            Helper.addEmptyScopePermission(authz, server, MANAGE_GROUP_MEMBERSHIP_PERMISSION_USERS, usersResource, manageGroupMembershipScope);
        }
        PolicyModel impersonatePermission = policyStore.findByName(ADMIN_IMPERSONATING_PERMISSION, server.getId());
        if (impersonatePermission == null) {
            Helper.addEmptyScopePermission(authz, server, ADMIN_IMPERSONATING_PERMISSION, usersResource, impersonateScope);
        }
        impersonatePermission = policyStore.findByName(USER_IMPERSONATED_PERMISSION, server.getId());
        if (impersonatePermission == null) {
            Helper.addEmptyScopePermission(authz, server, USER_IMPERSONATED_PERMISSION, usersResource, userImpersonatedScope);
        }
    }

    @Override
    public Map<String, String> getPermissions() {
        initialize();
        Map<String, String> scopes = new LinkedHashMap<>();
        scopes.put(AdminPermissionManagement.VIEW_SCOPE, viewPermission().getId());
        scopes.put(AdminPermissionManagement.MANAGE_SCOPE, managePermission().getId());
        scopes.put(MAP_ROLES_SCOPE, mapRolesPermission().getId());
        scopes.put(MANAGE_GROUP_MEMBERSHIP_SCOPE, manageGroupMembershipPermission().getId());
        scopes.put(IMPERSONATE_SCOPE, adminImpersonatingPermission().getId());
        scopes.put(USER_IMPERSONATED_SCOPE, userImpersonatedPermission().getId());
        return scopes;
    }

    @Override
    public boolean isPermissionsEnabled() {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return false;

        ResourceModel resource = resourceStore.findByName(USERS_RESOURCE, server.getId());
        if (resource == null) return false;

        PolicyModel policy = managePermission();

        return policy != null;
    }

    @Override
    public void setPermissionsEnabled(boolean enable) {
        if (enable) {
            initialize();
        } else {
            deletePermissionSetup();
        }
    }

    public boolean canManageDefault() {
        return root.hasOneAdminRole(AdminRoles.MANAGE_USERS);
    }

    @Override
    public ResourceModel resource() {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;

        return resourceStore.findByName(USERS_RESOURCE, server.getId());
    }

    @Override
    public PolicyModel managePermission() {
        return policyStore.findByName(MANAGE_PERMISSION_USERS, root.realmResourceServer().getId());
    }

    @Override
    public PolicyModel viewPermission() {
        return policyStore.findByName(VIEW_PERMISSION_USERS, root.realmResourceServer().getId());
    }

    @Override
    public PolicyModel manageGroupMembershipPermission() {
        return policyStore.findByName(MANAGE_GROUP_MEMBERSHIP_PERMISSION_USERS, root.realmResourceServer().getId());
    }

    @Override
    public PolicyModel mapRolesPermission() {
        return policyStore.findByName(MAP_ROLES_PERMISSION_USERS, root.realmResourceServer().getId());
    }


    @Override
    public PolicyModel adminImpersonatingPermission() {
        return policyStore.findByName(ADMIN_IMPERSONATING_PERMISSION, root.realmResourceServer().getId());
    }

    @Override
    public PolicyModel userImpersonatedPermission() {
        return policyStore.findByName(USER_IMPERSONATED_PERMISSION, root.realmResourceServer().getId());
    }

    /**
     * Is admin allowed to manage all users?  In Authz terms, does the admin have the "manage" scope for the Users Authz resource?
     * <p>
     * This method will follow the old default behavior (does the admin have the manage-users role) if any of these conditions
     * are met.:
     * - The admin is from the master realm managing a different realm
     * - If the Authz objects are not set up correctly for the Users resource in Authz
     * - The "manage" permission for the Users resource has an empty associatedPolicy list.
     * <p>
     * Otherwise, it will use the Authz policy engine to resolve this answer.
     *
     * @return
     */
    @Override
    public boolean canManage() {
        if (canManageDefault()) {
            return true;
        }

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(MgmtPermissions.MANAGE_SCOPE);
    }

    @Override
    public void requireManage() {
        if (!canManage()) {
            throw new ForbiddenException();
        }
    }


    /**
     * Does current admin have manage permissions for this particular user?
     *
     * @param user
     * @return
     */
    @Override
    public boolean canManage(UserModel user) {
        return canManage() || canManageByGroup(user);
    }

    @Override
    public void requireManage(UserModel user) {
        if (!canManage(user)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canQuery() {
        return canView() || root.hasOneAdminRole(AdminRoles.QUERY_USERS);
    }

    @Override
    public void requireQuery() {
        if (!canQuery()) {
            throw new ForbiddenException();
        }
    }

    /**
     * Is admin allowed to view all users?  In Authz terms, does the admin have the "view" scope for the Users Authz resource?
     * <p>
     * This method will follow the old default behavior (does the admin have the view-users role) if any of these conditions
     * are met.:
     * - The admin is from the master realm managing a different realm
     * - If the Authz objects are not set up correctly for the Users resource in Authz
     * - The "view" permission for the Users resource has an empty associatedPolicy list.
     * <p>
     * Otherwise, it will use the Authz policy engine to resolve this answer.
     *
     * @return
     */
    @Override
    public boolean canView() {
        if (canViewDefault() || canManageDefault()) {
            return true;
        }

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(MgmtPermissions.VIEW_SCOPE, MgmtPermissions.MANAGE_SCOPE);
    }

    /**
     * Does current admin have view permissions for this particular user?
     * <p>
     * Evaluates in this order. If any true, return true:
     * - canViewUsers
     * - canManageUsers
     *
     * @param user
     * @return
     */
    @Override
    public boolean canView(UserModel user) {
        return canView() || canViewByGroup(user);
    }

    @Override
    public void requireView(UserModel user) {
        if (!canView(user)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public void requireView() {
        if (!(canView())) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canClientImpersonate(ClientModel client, UserModel user) {
        ClientModelIdentity identity = new ClientModelIdentity(client);
        EvaluationContext context = new DefaultEvaluationContext(identity) {
            @Override
            public Map<String, Collection<String>> getBaseAttributes() {
                Map<String, Collection<String>> attributes = super.getBaseAttributes();
                attributes.put("kc.client.id", Arrays.asList(client.getClientId()));
                return attributes;
            }

        };
        return canImpersonate(context) && isImpersonatable(user);

    }

    @Override
    public boolean canImpersonate(UserModel user) {
        if (!canImpersonate()) {
            return false;
        }

        return isImpersonatable(user);
    }

    @Override
    public boolean isImpersonatable(UserModel user) {
        ResourceServerModel server = root.realmResourceServer();

        if (server == null) {
            return true;
        }

        ResourceModel resource = resourceStore.findByName(USERS_RESOURCE, server.getId());

        if (resource == null) {
            return true;
        }

        PolicyModel policy = authz.getStoreFactory().getPolicyStore().findByName(USER_IMPERSONATED_PERMISSION, server.getId());

        if (policy == null) {
            return true;
        }

        Set<PolicyModel> associatedPolicies = policy.getAssociatedPolicies();
        // if no policies attached to permission then just do default behavior
        if (associatedPolicies == null || associatedPolicies.isEmpty()) {
            return true;
        }

        return hasPermission(new DefaultEvaluationContext(new UserModelIdentity(root.realm, user)), USER_IMPERSONATED_SCOPE);
    }

    @Override
    public boolean canImpersonate() {
        if (root.hasOneAdminRole(ImpersonationConstants.IMPERSONATION_ROLE)) return true;

        Identity identity = root.identity;

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return canImpersonate(new DefaultEvaluationContext(identity));
    }

    @Override
    public void requireImpersonate(UserModel user) {
        if (!canImpersonate(user)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public Map<String, Boolean> getAccess(UserModel user) {
        Map<String, Boolean> map = new HashMap<>();
        map.put("view", canView(user));
        map.put("manage", canManage(user));
        map.put("mapRoles", canMapRoles(user));
        map.put("manageGroupMembership", canManageGroupMembership(user));
        map.put("impersonate", canImpersonate(user));
        return map;
    }

    @Override
    public boolean canMapRoles(UserModel user) {
        if (canManage(user)) return true;

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(MAP_ROLES_SCOPE);

    }

    @Override
    public void requireMapRoles(UserModel user) {
        if (!canMapRoles(user)) {
            throw new ForbiddenException();
        }

    }

    @Override
    public boolean canManageGroupMembership(UserModel user) {
        if (canManage(user)) return true;

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(MANAGE_GROUP_MEMBERSHIP_SCOPE);

    }

    @Override
    public void grantIfNoPermission(boolean grantIfNoPermission) {
        this.grantIfNoPermission = grantIfNoPermission;
    }

    @Override
    public void requireManageGroupMembership(UserModel user) {
        if (!canManageGroupMembership(user)) {
            throw new ForbiddenException();
        }

    }

    private boolean hasPermission(String... scopes) {
        return hasPermission(null, scopes);
    }

    private boolean hasPermission(EvaluationContext context, String... scopes) {
        ResourceServerModel server = root.realmResourceServer();

        if (server == null) {
            return false;
        }

        ResourceModel resource = resourceStore.findByName(USERS_RESOURCE, server.getId());
        List<String> expectedScopes = Arrays.asList(scopes);

        if (resource == null) {
            return grantIfNoPermission && expectedScopes.contains(MgmtPermissions.MANAGE_SCOPE) && expectedScopes.contains(MgmtPermissions.VIEW_SCOPE);
        }

        Collection<Permission> permissions;

        if (context == null) {
            permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server);
        } else {
            permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server, context);
        }

        for (Permission permission : permissions) {
            for (String scope : permission.getScopes()) {
                if (expectedScopes.contains(scope)) {
                    return true;
                }
            }
        }

        return false;
    }

    private void deletePermissionSetup() {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return;
        PolicyModel policy = managePermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        policy = viewPermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        policy = mapRolesPermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        policy = manageGroupMembershipPermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        policy = adminImpersonatingPermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        policy = userImpersonatedPermission();
        if (policy != null) {
            policyStore.delete(policy.getId());

        }
        ResourceModel usersResource = resourceStore.findByName(USERS_RESOURCE, server.getId());
        if (usersResource != null) {
            resourceStore.delete(usersResource.getId());
        }
    }

    private boolean canImpersonate(EvaluationContext context) {
        return hasPermission(context, IMPERSONATE_SCOPE);
    }

    private boolean evaluateHierarchy(UserModel user, Predicate<GroupModel> eval) {
        Set<GroupModel> visited = new HashSet<>();
        for (GroupModel group : user.getGroups()) {
            if (evaluateHierarchy(eval, group, visited)) return true;
        }
        return false;
    }

    private boolean evaluateHierarchy(Predicate<GroupModel> eval, GroupModel group, Set<GroupModel> visited) {
        if (visited.contains(group)) return false;
        if (eval.test(group)) {
            return true;
        }
        visited.add(group);
        if (group.getParent() == null) return false;
        return evaluateHierarchy(eval, group.getParent(), visited);
    }

    private boolean canManageByGroup(UserModel user) {
        return evaluateHierarchy(user, (group) -> root.groups().canManageMembers(group));

    }

    private boolean canViewByGroup(UserModel user) {
        return evaluateHierarchy(user, (group) -> root.groups().getGroupsWithViewPermission(group));
    }

    public boolean canViewDefault() {
        return root.hasOneAdminRole(AdminRoles.MANAGE_USERS, AdminRoles.VIEW_USERS);
    }
}
