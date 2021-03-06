/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authorization;

import com.hsbc.unified.iam.facade.model.authorization.PermissionTicketModel;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;

import java.util.HashMap;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserManagedPermissionUtil {

    public static void updatePolicy(PermissionTicketModel ticket, StoreFactory storeFactory) {
        ScopeModel scope = ticket.getScope();
        PolicyModel policy = ticket.getPolicy();

        if (policy == null) {
            HashMap<String, String> filter = new HashMap<>();

            filter.put(PermissionTicketModel.OWNER, ticket.getOwner());
            filter.put(PermissionTicketModel.REQUESTER, ticket.getRequester());
            filter.put(PermissionTicketModel.RESOURCE, ticket.getResource().getId());
            filter.put(PermissionTicketModel.POLICY_IS_NOT_NULL, Boolean.TRUE.toString());

            List<PermissionTicketModel> tickets = storeFactory.getPermissionTicketStore().find(filter, ticket.getResourceServer().getId(), -1, 1);

            if (!tickets.isEmpty()) {
                policy = tickets.iterator().next().getPolicy();
            }
        }

        if (ticket.isGranted()) {
            if (policy == null) {
                policy = createUserManagedPermission(ticket, storeFactory);
            }

            if (scope != null && !policy.getScopes().contains(scope)) {
                policy.addScope(scope);
            }

            ticket.setPolicy(policy);
        } else if (scope != null) {
            policy.removeScope(scope);
            ticket.setPolicy(null);
        }
    }

    public static void removePolicy(PermissionTicketModel ticket, StoreFactory storeFactory) {
        PolicyModel policy = ticket.getPolicy();

        if (policy != null) {
            HashMap<String, String> filter = new HashMap<>();

            filter.put(PermissionTicketModel.OWNER, ticket.getOwner());
            filter.put(PermissionTicketModel.REQUESTER, ticket.getRequester());
            filter.put(PermissionTicketModel.RESOURCE, ticket.getResource().getId());
            filter.put(PermissionTicketModel.GRANTED, Boolean.TRUE.toString());

            List<PermissionTicketModel> tickets = storeFactory.getPermissionTicketStore().find(filter, ticket.getResourceServer().getId(), -1, -1);

            if (tickets.isEmpty()) {
                PolicyStore policyStore = storeFactory.getPolicyStore();

                for (PolicyModel associatedPolicy : policy.getAssociatedPolicies()) {
                    policyStore.delete(associatedPolicy.getId());
                }

                policyStore.delete(policy.getId());
            } else if (ticket.getScope() != null) {
                policy.removeScope(ticket.getScope());
            }
        }
    }

    private static PolicyModel createUserManagedPermission(PermissionTicketModel ticket, StoreFactory storeFactory) {
        PolicyStore policyStore = storeFactory.getPolicyStore();
        UserPolicyRepresentation userPolicyRep = new UserPolicyRepresentation();

        userPolicyRep.setName(KeycloakModelUtils.generateId());
        userPolicyRep.addUser(ticket.getRequester());

        PolicyModel userPolicy = policyStore.create(userPolicyRep, ticket.getResourceServer());

        userPolicy.setOwner(ticket.getOwner());

        PolicyRepresentation policyRep = new PolicyRepresentation();

        policyRep.setName(KeycloakModelUtils.generateId());
        policyRep.setType("uma");
        policyRep.addPolicy(userPolicy.getId());

        PolicyModel policy = policyStore.create(policyRep, ticket.getResourceServer());

        policy.setOwner(ticket.getOwner());
        policy.addResource(ticket.getResource());

        ScopeModel scope = ticket.getScope();

        if (scope != null) {
            policy.addScope(scope);
        }

        return policy;
    }

}
