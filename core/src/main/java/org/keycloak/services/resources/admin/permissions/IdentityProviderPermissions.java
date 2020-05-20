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
import org.keycloak.authorization.common.ClientModelIdentity;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.model.PolicyModel;
import org.keycloak.authorization.model.ResourceModel;
import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.authorization.model.ScopeModel;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.keycloak.services.resources.admin.permissions.AdminPermissionManagement.TOKEN_EXCHANGE;

/**
 * Manages default policies for identity providers.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class IdentityProviderPermissions implements IdentityProviderPermissionManagement {
    private static final Logger LOG = LoggerFactory.getLogger(IdentityProviderPermissions.class);
    protected final KeycloakSession session;
    protected final RealmModel realm;
    protected final AuthorizationProvider authz;
    protected final MgmtPermissions root;

    public IdentityProviderPermissions(KeycloakSession session, RealmModel realm, AuthorizationProvider authz, MgmtPermissions root) {
        this.session = session;
        this.realm = realm;
        this.authz = authz;
        this.root = root;
    }

    private String getResourceName(IdentityProviderModel idp) {
        return "idp.resource." + idp.getInternalId();
    }

    private String getExchangeToPermissionName(IdentityProviderModel idp) {
        return TOKEN_EXCHANGE + ".permission.idp." + idp.getInternalId();
    }

    private void initialize(IdentityProviderModel idp) {
        ResourceServerModel server = root.initializeRealmResourceServer();
        ScopeModel exchangeToScope = root.initializeScope(TOKEN_EXCHANGE, server);

        String resourceName = getResourceName(idp);
        ResourceModel resource = authz.getStoreFactory().getResourceStore().findByName(resourceName, server.getId());
        if (resource == null) {
            resource = authz.getStoreFactory().getResourceStore().create(resourceName, server, server.getId());
            resource.setType("IdentityProvider");
            Set<ScopeModel> scopeset = new HashSet<>();
            scopeset.add(exchangeToScope);
            resource.updateScopes(scopeset);
        }
        String exchangeToPermissionName = getExchangeToPermissionName(idp);
        PolicyModel exchangeToPermission = authz.getStoreFactory().getPolicyStore().findByName(exchangeToPermissionName, server.getId());
        if (exchangeToPermission == null) {
            Helper.addEmptyScopePermission(authz, server, exchangeToPermissionName, resource, exchangeToScope);
        }
    }

    private void deletePolicy(String name, ResourceServerModel server) {
        PolicyModel policy = authz.getStoreFactory().getPolicyStore().findByName(name, server.getId());
        if (policy != null) {
            authz.getStoreFactory().getPolicyStore().delete(policy.getId());
        }

    }

    private void deletePermissions(IdentityProviderModel idp) {
        ResourceServerModel server = root.initializeRealmResourceServer();
        if (server == null) return;
        deletePolicy(getExchangeToPermissionName(idp), server);
        ResourceModel resource = authz.getStoreFactory().getResourceStore().findByName(getResourceName(idp), server.getId());
        ;
        if (resource != null) authz.getStoreFactory().getResourceStore().delete(resource.getId());
    }

    @Override
    public boolean isPermissionsEnabled(IdentityProviderModel idp) {
        ResourceServerModel server = root.initializeRealmResourceServer();
        if (server == null) return false;

        return authz.getStoreFactory().getResourceStore().findByName(getResourceName(idp), server.getId()) != null;
    }

    @Override
    public void setPermissionsEnabled(IdentityProviderModel idp, boolean enable) {
        if (enable) {
            initialize(idp);
        } else {
            deletePermissions(idp);
        }
    }


    private ScopeModel exchangeToScope(ResourceServerModel server) {
        return authz.getStoreFactory().getScopeStore().findByName(TOKEN_EXCHANGE, server.getId());
    }

    @Override
    public ResourceModel resource(IdentityProviderModel idp) {
        ResourceServerModel server = root.initializeRealmResourceServer();
        if (server == null) return null;
        ResourceModel resource = authz.getStoreFactory().getResourceStore().findByName(getResourceName(idp), server.getId());
        if (resource == null) return null;
        return resource;
    }


    @Override
    public Map<String, String> getPermissions(IdentityProviderModel idp) {
        initialize(idp);
        Map<String, String> scopes = new LinkedHashMap<>();
        scopes.put(TOKEN_EXCHANGE, exchangeToPermission(idp).getId());
        return scopes;
    }

    @Override
    public boolean canExchangeTo(ClientModel authorizedClient, IdentityProviderModel to) {

        if (!authorizedClient.equals(to)) {
            ResourceServerModel server = root.initializeRealmResourceServer();
            if (server == null) {
                LOG.debug("No resource server set up for target idp");
                return false;
            }

            ResourceModel resource = authz.getStoreFactory().getResourceStore().findByName(getResourceName(to), server.getId());
            if (resource == null) {
                LOG.debug("No resource object set up for target idp");
                return false;
            }

            PolicyModel policy = authz.getStoreFactory().getPolicyStore().findByName(getExchangeToPermissionName(to), server.getId());
            if (policy == null) {
                LOG.debug("No permission object set up for target idp");
                return false;
            }

            Set<PolicyModel> associatedPolicies = policy.getAssociatedPolicies();
            // if no policies attached to permission then just do default behavior
            if (associatedPolicies == null || associatedPolicies.isEmpty()) {
                LOG.debug("No policies set up for permission on target idp");
                return false;
            }

            ScopeModel scope = exchangeToScope(server);
            if (scope == null) {
                LOG.debug(TOKEN_EXCHANGE + " not initialized");
                return false;
            }
            ClientModelIdentity identity = new ClientModelIdentity(session, authorizedClient);
            EvaluationContext context = new DefaultEvaluationContext(identity, session) {
                @Override
                public Map<String, Collection<String>> getBaseAttributes() {
                    Map<String, Collection<String>> attributes = super.getBaseAttributes();
                    attributes.put("kc.client.id", Arrays.asList(authorizedClient.getClientId()));
                    return attributes;
                }

            };
            return root.evaluatePermission(resource, server, context, scope);
        }
        return true;
    }

    @Override
    public PolicyModel exchangeToPermission(IdentityProviderModel idp) {
        ResourceServerModel server = root.initializeRealmResourceServer();
        if (server == null) return null;
        return authz.getStoreFactory().getPolicyStore().findByName(getExchangeToPermissionName(idp), server.getId());
    }

}
