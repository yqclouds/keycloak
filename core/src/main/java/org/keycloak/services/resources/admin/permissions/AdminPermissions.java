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

import com.hsbc.unified.iam.entity.events.ClientRemovedEvent;
import com.hsbc.unified.iam.entity.events.GroupRemovedEvent;
import com.hsbc.unified.iam.entity.events.RoleRemovedEvent;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderEventManager;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AdminPermissions {
    public static AdminPermissionEvaluator evaluator(RealmModel realm, AdminAuth auth) {
        return new MgmtPermissions(realm, auth);
    }

    public static AdminPermissionEvaluator evaluator(RealmModel realm, RealmModel adminsRealm, UserModel admin) {
        return new MgmtPermissions(realm, adminsRealm, admin);
    }

    public static RealmsPermissionEvaluator realms(AdminAuth auth) {
        return new MgmtPermissions(auth);
    }

    public static RealmsPermissionEvaluator realms(RealmModel adminsRealm, UserModel admin) {
        return new MgmtPermissions(adminsRealm, admin);
    }

    public static AdminPermissionManagement management(RealmModel realm) {
        return new MgmtPermissions(realm);
    }

    public static void registerListener(ProviderEventManager manager) {
        manager.register(event -> {
            if (event instanceof RoleRemovedEvent) {
                RoleRemovedEvent cast = (RoleRemovedEvent) event;
                RoleModel role = (RoleModel) cast.getSource();
                RealmModel realm;
                if (role.getContainer() instanceof ClientModel) {
                    realm = ((ClientModel) role.getContainer()).getRealm();

                } else {
                    realm = (RealmModel) role.getContainer();
                }
                management(realm).roles().setPermissionsEnabled(role, false);
            } else if (event instanceof ClientRemovedEvent) {
                ClientRemovedEvent cast = (ClientRemovedEvent) event;
                management(((ClientModel) cast.getSource()).getRealm()).clients()
                        .setPermissionsEnabled((ClientModel) cast.getSource(), false);
            } else if (event instanceof GroupRemovedEvent) {
                GroupRemovedEvent cast = (GroupRemovedEvent) event;
                management(cast.getRealm()).groups().setPermissionsEnabled(cast.getGroup(), false);
            }
        });
    }
}
