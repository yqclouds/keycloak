package com.hsbc.unified.iam.web.admin.resources;

import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/users-management-permissions",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmUsersManagementPermissionsResource {
    @Autowired
    private RealmModel realm;

    @RequestMapping(method = RequestMethod.GET)
    public ManagementPermissionReference getUserMgmtPermissions() {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (permissions.users().isPermissionsEnabled()) {
            return toUsersMgmtRef(permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

    @RequestMapping(method = RequestMethod.PUT)
    public ManagementPermissionReference setUsersManagementPermissionsEnabled(ManagementPermissionReference ref) {
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.users().setPermissionsEnabled(ref.isEnabled());
        if (ref.isEnabled()) {
            return toUsersMgmtRef(permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

    public ManagementPermissionReference toUsersMgmtRef(AdminPermissionManagement permissions) {
        ManagementPermissionReference ref = new ManagementPermissionReference();
        ref.setEnabled(true);
        ref.setResource(permissions.users().resource().getId());
        Map<String, String> scopes = permissions.users().getPermissions();
        ref.setScopePermissions(scopes);
        return ref;
    }
}
