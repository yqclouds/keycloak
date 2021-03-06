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

import org.keycloak.authorization.AuthorizationProvider;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.GroupModel;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ForbiddenException;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class GroupPermissions implements GroupPermissionEvaluator, GroupPermissionManagement {

    private static final String MANAGE_MEMBERSHIP_SCOPE = "manage-membership";
    private static final String MANAGE_MEMBERS_SCOPE = "manage-members";
    private static final String VIEW_MEMBERS_SCOPE = "view-members";
    private static final String RESOURCE_NAME_PREFIX = "group.resource.";

    private final AuthorizationProvider authz;
    private final MgmtPermissions root;
    private final ResourceStore resourceStore;
    private final PolicyStore policyStore;

    GroupPermissions(AuthorizationProvider authz, MgmtPermissions root) {
        this.authz = authz;
        this.root = root;
        resourceStore = authz.getStoreFactory().getResourceStore();
        policyStore = authz.getStoreFactory().getPolicyStore();
    }

    private static String getGroupResourceName(GroupModel group) {
        return RESOURCE_NAME_PREFIX + group.getId();
    }


    private static String getManagePermissionGroup(GroupModel group) {
        return "manage.permission.group." + group.getId();
    }

    private static String getManageMembersPermissionGroup(GroupModel group) {
        return "manage.members.permission.group." + group.getId();
    }

    private static String getManageMembershipPermissionGroup(GroupModel group) {
        return "manage.membership.permission.group." + group.getId();
    }

    private static String getViewPermissionGroup(GroupModel group) {
        return "view.permission.group." + group.getId();
    }

    private static String getViewMembersPermissionGroup(GroupModel group) {
        return "view.members.permission.group." + group.getId();
    }

    private void initialize(GroupModel group) {
        root.initializeRealmResourceServer();
        root.initializeRealmDefaultScopes();
        ResourceServerModel server = root.realmResourceServer();
        ScopeModel manageScope = root.realmManageScope();
        ScopeModel viewScope = root.realmViewScope();
        ScopeModel manageMembersScope = root.initializeRealmScope(MANAGE_MEMBERS_SCOPE);
        ScopeModel viewMembersScope = root.initializeRealmScope(VIEW_MEMBERS_SCOPE);
        ScopeModel manageMembershipScope = root.initializeRealmScope(MANAGE_MEMBERSHIP_SCOPE);

        String groupResourceName = getGroupResourceName(group);
        ResourceModel groupResource = resourceStore.findByName(groupResourceName, server.getId());
        if (groupResource == null) {
            groupResource = resourceStore.create(groupResourceName, server, server.getId());
            Set<ScopeModel> scopeset = new HashSet<>();
            scopeset.add(manageScope);
            scopeset.add(viewScope);
            scopeset.add(viewMembersScope);
            scopeset.add(manageMembershipScope);
            scopeset.add(manageMembersScope);
            groupResource.updateScopes(scopeset);
            groupResource.setType("Group");
        }
        String managePermissionName = getManagePermissionGroup(group);
        PolicyModel managePermission = policyStore.findByName(managePermissionName, server.getId());
        if (managePermission == null) {
            Helper.addEmptyScopePermission(authz, server, managePermissionName, groupResource, manageScope);
        }
        String viewPermissionName = getViewPermissionGroup(group);
        PolicyModel viewPermission = policyStore.findByName(viewPermissionName, server.getId());
        if (viewPermission == null) {
            Helper.addEmptyScopePermission(authz, server, viewPermissionName, groupResource, viewScope);
        }
        String manageMembersPermissionName = getManageMembersPermissionGroup(group);
        PolicyModel manageMembersPermission = policyStore.findByName(manageMembersPermissionName, server.getId());
        if (manageMembersPermission == null) {
            Helper.addEmptyScopePermission(authz, server, manageMembersPermissionName, groupResource, manageMembersScope);
        }
        String viewMembersPermissionName = getViewMembersPermissionGroup(group);
        PolicyModel viewMembersPermission = policyStore.findByName(viewMembersPermissionName, server.getId());
        if (viewMembersPermission == null) {
            Helper.addEmptyScopePermission(authz, server, viewMembersPermissionName, groupResource, viewMembersScope);
        }
        String manageMembershipPermissionName = getManageMembershipPermissionGroup(group);
        PolicyModel manageMembershipPermission = policyStore.findByName(manageMembershipPermissionName, server.getId());
        if (manageMembershipPermission == null) {
            Helper.addEmptyScopePermission(authz, server, manageMembershipPermissionName, groupResource, manageMembershipScope);
        }

    }

    @Override
    public boolean canList() {
        return canView() || root.hasOneAdminRole(AdminRoles.VIEW_USERS, AdminRoles.MANAGE_USERS, AdminRoles.QUERY_GROUPS);
    }

    @Override
    public void requireList() {
        if (!canList()) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean isPermissionsEnabled(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return false;

        return resourceStore.findByName(getGroupResourceName(group), server.getId()) != null;
    }

    @Override
    public void setPermissionsEnabled(GroupModel group, boolean enable) {
        if (enable) {
            initialize(group);
        } else {
            deletePermissions(group);
        }
    }

    @Override
    public PolicyModel viewMembersPermission(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        return policyStore.findByName(getViewMembersPermissionGroup(group), server.getId());
    }

    @Override
    public PolicyModel manageMembersPermission(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        return policyStore.findByName(getManageMembersPermissionGroup(group), server.getId());
    }

    @Override
    public PolicyModel manageMembershipPermission(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        return policyStore.findByName(getManageMembershipPermissionGroup(group), server.getId());
    }

    @Override
    public PolicyModel viewPermission(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        return policyStore.findByName(getViewPermissionGroup(group), server.getId());
    }

    @Override
    public PolicyModel managePermission(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        return policyStore.findByName(getManagePermissionGroup(group), server.getId());
    }

    @Override
    public ResourceModel resource(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        ResourceModel resource = resourceStore.findByName(getGroupResourceName(group), server.getId());
        if (resource == null) return null;
        return resource;
    }

    @Override
    public Map<String, String> getPermissions(GroupModel group) {
        initialize(group);
        Map<String, String> scopes = new LinkedHashMap<>();
        scopes.put(AdminPermissionManagement.VIEW_SCOPE, viewPermission(group).getId());
        scopes.put(AdminPermissionManagement.MANAGE_SCOPE, managePermission(group).getId());
        scopes.put(VIEW_MEMBERS_SCOPE, viewMembersPermission(group).getId());
        scopes.put(MANAGE_MEMBERS_SCOPE, manageMembersPermission(group).getId());
        scopes.put(MANAGE_MEMBERSHIP_SCOPE, manageMembershipPermission(group).getId());
        return scopes;
    }

    @Override
    public boolean canManage(GroupModel group) {
        if (canManage()) {
            return true;
        }

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(group, MgmtPermissions.MANAGE_SCOPE);
    }

    @Override
    public void requireManage(GroupModel group) {
        if (!canManage(group)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canView(GroupModel group) {
        if (canView() || canManage()) {
            return true;
        }

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(group, MgmtPermissions.VIEW_SCOPE, MgmtPermissions.MANAGE_SCOPE);
    }

    @Override
    public void requireView(GroupModel group) {
        if (!canView(group)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canManage() {
        return root.users().canManageDefault();
    }

    @Override
    public void requireManage() {
        if (!canManage()) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canView() {
        return root.users().canViewDefault();
    }

    @Override
    public void requireView() {
        if (!canView()) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean getGroupsWithViewPermission(GroupModel group) {
        if (root.users().canView() || root.users().canManage()) {
            return true;
        }

        if (!root.isAdminSameRealm()) {
            return false;
        }

        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return false;

        return hasPermission(group, VIEW_MEMBERS_SCOPE, MANAGE_MEMBERS_SCOPE);
    }

    @Override
    public Set<String> getGroupsWithViewPermission() {
        if (root.users().canView() || root.users().canManage()) return Collections.emptySet();

        if (!root.isAdminSameRealm()) {
            return Collections.emptySet();
        }

        ResourceServerModel server = root.realmResourceServer();

        if (server == null) {
            return Collections.emptySet();
        }

        Set<String> granted = new HashSet<>();

        resourceStore.findByType("Group", server.getId(), resource -> {
            if (hasPermission(resource, null, VIEW_MEMBERS_SCOPE, MANAGE_MEMBERS_SCOPE)) {
                granted.add(resource.getName().substring(RESOURCE_NAME_PREFIX.length()));
            }
        });

        return granted;
    }

    @Override
    public void requireViewMembers(GroupModel group) {
        if (!getGroupsWithViewPermission(group)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public boolean canManageMembers(GroupModel group) {
        if (root.users().canManage()) return true;

        if (!root.isAdminSameRealm()) {
            return false;
        }

        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return false;

        return hasPermission(group, MANAGE_MEMBERS_SCOPE);
    }

    @Override
    public boolean canManageMembership(GroupModel group) {
        if (canManage(group)) return true;

        if (!root.isAdminSameRealm()) {
            return false;
        }

        return hasPermission(group, MANAGE_MEMBERSHIP_SCOPE);
    }

    @Override
    public void requireManageMembership(GroupModel group) {
        if (!canManageMembership(group)) {
            throw new ForbiddenException();
        }
    }

    @Override
    public Map<String, Boolean> getAccess(GroupModel group) {
        Map<String, Boolean> map = new HashMap<>();
        map.put("view", canView(group));
        map.put("manage", canManage(group));
        map.put("manageMembership", canManageMembership(group));
        return map;
    }

    private boolean hasPermission(GroupModel group, String... scopes) {
        return hasPermission(group, null, scopes);
    }

    private boolean hasPermission(GroupModel group, EvaluationContext context, String... scopes) {
        ResourceServerModel server = root.realmResourceServer();

        if (server == null) {
            return false;
        }

        ResourceModel resource = resourceStore.findByName(getGroupResourceName(group), server.getId());

        if (resource == null) {
            return false;
        }

        return hasPermission(resource, context, scopes);
    }

    private boolean hasPermission(ResourceModel resource, EvaluationContext context, String... scopes) {
        ResourceServerModel server = root.realmResourceServer();
        Collection<Permission> permissions;

        if (context == null) {
            permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server);
        } else {
            permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server, context);
        }

        List<String> expectedScopes = Arrays.asList(scopes);


        for (Permission permission : permissions) {
            for (String scope : permission.getScopes()) {
                if (expectedScopes.contains(scope)) {
                    return true;
                }
            }
        }

        return false;
    }

    private ResourceModel groupResource(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return null;
        String groupResourceName = getGroupResourceName(group);
        return resourceStore.findByName(groupResourceName, server.getId());
    }

    private void deletePermissions(GroupModel group) {
        ResourceServerModel server = root.realmResourceServer();
        if (server == null) return;
        PolicyModel managePermission = managePermission(group);
        if (managePermission != null) {
            policyStore.delete(managePermission.getId());
        }
        PolicyModel viewPermission = viewPermission(group);
        if (viewPermission != null) {
            policyStore.delete(viewPermission.getId());
        }
        PolicyModel manageMembersPermission = manageMembersPermission(group);
        if (manageMembersPermission != null) {
            policyStore.delete(manageMembersPermission.getId());
        }
        PolicyModel viewMembersPermission = viewMembersPermission(group);
        if (viewMembersPermission != null) {
            policyStore.delete(viewMembersPermission.getId());
        }
        PolicyModel manageMembershipPermission = manageMembershipPermission(group);
        if (manageMembershipPermission != null) {
            policyStore.delete(manageMembershipPermission.getId());
        }
        ResourceModel resource = groupResource(group);
        if (resource != null) resourceStore.delete(resource.getId());
    }
}
