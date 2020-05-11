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

package org.keycloak.constants;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ServiceUrlConstants {
    String AUTH_PATH = "/realms/{realm-name}/protocol/openid-connect/auth";
    String TOKEN_PATH = "/realms/{realm-name}/protocol/openid-connect/token";
    String TOKEN_SERVICE_LOGOUT_PATH = "/realms/{realm-name}/protocol/openid-connect/logout";
    String ACCOUNT_SERVICE_PATH = "/realms/{realm-name}/account";
    String REALM_INFO_PATH = "/realms/{realm-name}";
    String CLIENTS_MANAGEMENT_REGISTER_NODE_PATH = "/realms/{realm-name}/clients-managements/register-node";
    String CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH = "/realms/{realm-name}/clients-managements/unregister-node";
    String JWKS_URL = "/realms/{realm-name}/protocol/openid-connect/certs";
    String DISCOVERY_URL = "/realms/{realm-name}/.well-known/openid-configuration";
    String AUTHZ_DISCOVERY_URL = "/realms/{realm-name}/.well-known/uma2-configuration";
}
