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

import org.keycloak.authorization.model.PolicyModel;
import org.keycloak.authorization.model.ResourceModel;
import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.models.ClientModel;

import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ClientPermissionManagement {
    public static final String MAP_ROLES_SCOPE = "map-roles";
    public static final String MAP_ROLES_CLIENT_SCOPE = "map-roles-client-scope";
    public static final String MAP_ROLES_COMPOSITE_SCOPE = "map-roles-composite";
    public static final String CONFIGURE_SCOPE = "configure";

    boolean isPermissionsEnabled(ClientModel client);

    void setPermissionsEnabled(ClientModel client, boolean enable);

    ResourceModel resource(ClientModel client);

    Map<String, String> getPermissions(ClientModel client);

    boolean canExchangeTo(ClientModel authorizedClient, ClientModel to);

    PolicyModel exchangeToPermission(ClientModel client);

    PolicyModel mapRolesPermission(ClientModel client);

    PolicyModel mapRolesClientScopePermission(ClientModel client);

    PolicyModel mapRolesCompositePermission(ClientModel client);

    PolicyModel managePermission(ClientModel client);

    PolicyModel configurePermission(ClientModel client);

    PolicyModel viewPermission(ClientModel client);

    ResourceServerModel resourceServer(ClientModel client);
}
