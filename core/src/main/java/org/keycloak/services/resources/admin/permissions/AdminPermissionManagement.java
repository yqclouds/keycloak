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
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.models.ClientModel;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface AdminPermissionManagement {
    public static final String MANAGE_SCOPE = "manage";
    public static final String VIEW_SCOPE = "view";
    public static final String TOKEN_EXCHANGE = "token-exchange";

    ClientModel getRealmManagementClient();

    AuthorizationProvider authz();

    RolePermissionManagement roles();

    UserPermissionManagement users();

    GroupPermissionManagement groups();

    ClientPermissionManagement clients();

    IdentityProviderPermissionManagement idps();

    ResourceServerModel realmResourceServer();
}
