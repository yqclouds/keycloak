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
package org.keycloak.authorization.policy.provider.permission;

import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.*;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation.GroupDefinition;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation.RoleDefinition;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component("UMAPolicyProviderFactory")
@ProviderFactory(id = "uma", providerClasses = PolicyProvider.class)
public class UMAPolicyProviderFactory implements PolicyProviderFactory<UmaPermissionRepresentation> {

    private UMAPolicyProvider provider = new UMAPolicyProvider();

    @Override
    public String getName() {
        return "UMA";
    }

    @Override
    public String getGroup() {
        return "Others";
    }

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return provider;
    }

    @Override
    public PolicyProvider create() {
        return provider;
    }

    @Override
    public void onCreate(PolicyModel policy, UmaPermissionRepresentation representation, AuthorizationProvider authorization) {
        policy.setOwner(representation.getOwner());
        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();
        Set<String> roles = representation.getRoles();

        if (roles != null) {
            for (String role : roles) {
                createRolePolicy(policy, policyStore, role, representation.getOwner());
            }
        }

        Set<String> groups = representation.getGroups();

        if (groups != null) {
            for (String group : groups) {
                createGroupPolicy(policy, policyStore, group, representation.getOwner());
            }
        }

        Set<String> clients = representation.getClients();

        if (clients != null) {
            for (String client : clients) {
                createClientPolicy(policy, policyStore, client, representation.getOwner());
            }
        }

        Set<String> users = representation.getUsers();

        if (users != null) {
            for (String user : users) {
                createUserPolicy(policy, policyStore, user, representation.getOwner());
            }
        }

        String condition = representation.getCondition();

        if (condition != null) {
            createJSPolicy(policy, policyStore, condition, representation.getOwner());
        }
    }

    @Override
    public void onUpdate(PolicyModel policy, UmaPermissionRepresentation representation, AuthorizationProvider authorization) {
        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();
        Set<PolicyModel> associatedPolicies = policy.getAssociatedPolicies();

        for (PolicyModel associatedPolicy : associatedPolicies) {
            AbstractPolicyRepresentation associatedRep = modelToRepresentation.toRepresentation(associatedPolicy, authorization, false, false);

            if ("role".equals(associatedRep.getType())) {
                RolePolicyRepresentation rep = RolePolicyRepresentation.class.cast(associatedRep);

                rep.setRoles(new HashSet<>());

                Set<String> updatedRoles = representation.getRoles();

                if (updatedRoles != null) {
                    for (String role : updatedRoles) {
                        rep.addRole(role);
                    }
                }

                if (rep.getRoles().isEmpty()) {
                    policyStore.delete(associatedPolicy.getId());
                } else {
                    RepresentationToModel.toModel(rep, authorization, associatedPolicy);
                }
            } else if ("js".equals(associatedRep.getType())) {
                JSPolicyRepresentation rep = JSPolicyRepresentation.class.cast(associatedRep);

                if (representation.getCondition() != null) {
                    rep.setCode(representation.getCondition());
                    RepresentationToModel.toModel(rep, authorization, associatedPolicy);
                } else {
                    policyStore.delete(associatedPolicy.getId());
                }
            } else if ("group".equals(associatedRep.getType())) {
                GroupPolicyRepresentation rep = GroupPolicyRepresentation.class.cast(associatedRep);

                rep.setGroups(new HashSet<>());

                Set<String> updatedGroups = representation.getGroups();

                if (updatedGroups != null) {
                    for (String group : updatedGroups) {
                        rep.addGroupPath(group);
                    }
                }

                if (rep.getGroups().isEmpty()) {
                    policyStore.delete(associatedPolicy.getId());
                } else {
                    RepresentationToModel.toModel(rep, authorization, associatedPolicy);
                }
            } else if ("client".equals(associatedRep.getType())) {
                ClientPolicyRepresentation rep = ClientPolicyRepresentation.class.cast(associatedRep);

                rep.setClients(new HashSet<>());

                Set<String> updatedClients = representation.getClients();

                if (updatedClients != null) {
                    for (String client : updatedClients) {
                        rep.addClient(client);
                    }
                }

                if (rep.getClients().isEmpty()) {
                    policyStore.delete(associatedPolicy.getId());
                } else {
                    RepresentationToModel.toModel(rep, authorization, associatedPolicy);
                }
            } else if ("user".equals(associatedRep.getType())) {
                UserPolicyRepresentation rep = UserPolicyRepresentation.class.cast(associatedRep);

                rep.setUsers(new HashSet<>());

                Set<String> updatedUsers = representation.getUsers();

                if (updatedUsers != null) {
                    for (String user : updatedUsers) {
                        rep.addUser(user);
                    }
                }

                if (rep.getUsers().isEmpty()) {
                    policyStore.delete(associatedPolicy.getId());
                } else {
                    RepresentationToModel.toModel(rep, authorization, associatedPolicy);
                }
            }
        }

        Set<String> updatedRoles = representation.getRoles();

        if (updatedRoles != null) {
            boolean createPolicy = true;

            for (PolicyModel associatedPolicy : associatedPolicies) {
                if ("role".equals(associatedPolicy.getType())) {
                    createPolicy = false;
                }
            }

            if (createPolicy) {
                for (String role : updatedRoles) {
                    createRolePolicy(policy, policyStore, role, policy.getOwner());
                }
            }
        }

        Set<String> updatedGroups = representation.getGroups();

        if (updatedGroups != null) {
            boolean createPolicy = true;

            for (PolicyModel associatedPolicy : associatedPolicies) {
                if ("group".equals(associatedPolicy.getType())) {
                    createPolicy = false;
                }
            }

            if (createPolicy) {
                for (String group : updatedGroups) {
                    createGroupPolicy(policy, policyStore, group, policy.getOwner());
                }
            }
        }

        Set<String> updatedClients = representation.getClients();

        if (updatedClients != null) {
            boolean createPolicy = true;

            for (PolicyModel associatedPolicy : associatedPolicies) {
                if ("client".equals(associatedPolicy.getType())) {
                    createPolicy = false;
                }
            }

            if (createPolicy) {
                for (String client : updatedClients) {
                    createClientPolicy(policy, policyStore, client, policy.getOwner());
                }
            }
        }

        Set<String> updatedUsers = representation.getUsers();

        if (updatedUsers != null) {
            boolean createPolicy = true;

            for (PolicyModel associatedPolicy : associatedPolicies) {
                if ("user".equals(associatedPolicy.getType())) {
                    createPolicy = false;
                }
            }

            if (createPolicy) {
                for (String user : updatedUsers) {
                    createUserPolicy(policy, policyStore, user, policy.getOwner());
                }
            }
        }

        String condition = representation.getCondition();

        if (condition != null) {
            boolean createPolicy = true;

            for (PolicyModel associatedPolicy : associatedPolicies) {
                if ("js".equals(associatedPolicy.getType())) {
                    createPolicy = false;
                }
            }

            if (createPolicy) {
                createJSPolicy(policy, policyStore, condition, policy.getOwner());
            }
        }
    }

    @Override
    public void onImport(PolicyModel policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
    }

    @Autowired
    private UserProvider userProvider;
    @Autowired
    private ModelToRepresentation modelToRepresentation;

    @Override
    public UmaPermissionRepresentation toRepresentation(PolicyModel policy, AuthorizationProvider authorization) {
        UmaPermissionRepresentation representation = new UmaPermissionRepresentation();

        representation.setScopes(policy.getScopes().stream().map(ScopeModel::getName).collect(Collectors.toSet()));
        representation.setOwner(policy.getOwner());

        for (PolicyModel associatedPolicy : policy.getAssociatedPolicies()) {
            AbstractPolicyRepresentation associatedRep = modelToRepresentation.toRepresentation(associatedPolicy, authorization, false, false);
            RealmModel realm = authorization.getRealm();

            if ("role".equals(associatedRep.getType())) {
                RolePolicyRepresentation rep = RolePolicyRepresentation.class.cast(associatedRep);

                for (RoleDefinition definition : rep.getRoles()) {
                    RoleModel role = realm.getRoleById(definition.getId());

                    if (role.isClientRole()) {
                        representation.addClientRole(ClientModel.class.cast(role.getContainer()).getClientId(), role.getName());
                    } else {
                        representation.addRole(role.getName());
                    }
                }
            } else if ("js".equals(associatedRep.getType())) {
                JSPolicyRepresentation rep = JSPolicyRepresentation.class.cast(associatedRep);
                representation.setCondition(rep.getCode());
            } else if ("group".equals(associatedRep.getType())) {
                GroupPolicyRepresentation rep = GroupPolicyRepresentation.class.cast(associatedRep);

                for (GroupDefinition definition : rep.getGroups()) {
                    representation.addGroup(ModelToRepresentation.buildGroupPath(realm.getGroupById(definition.getId())));
                }
            } else if ("client".equals(associatedRep.getType())) {
                ClientPolicyRepresentation rep = ClientPolicyRepresentation.class.cast(associatedRep);

                for (String client : rep.getClients()) {
                    representation.addClient(realm.getClientById(client).getClientId());
                }
            } else if ("user".equals(associatedPolicy.getType())) {
                UserPolicyRepresentation rep = UserPolicyRepresentation.class.cast(associatedRep);

                for (String user : rep.getUsers()) {
                    representation.addUser(userProvider.getUserById(user, realm).getUsername());
                }
            }
        }

        return representation;
    }

    @Override
    public Class<UmaPermissionRepresentation> getRepresentationType() {
        return UmaPermissionRepresentation.class;
    }

    @Override
    public void onRemove(PolicyModel policy, AuthorizationProvider authorization) {
        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();

        for (PolicyModel associatedPolicy : policy.getAssociatedPolicies()) {
            policyStore.delete(associatedPolicy.getId());
        }
    }

    @Override
    public String getId() {
        return "uma";
    }

    private void createJSPolicy(PolicyModel policy, PolicyStore policyStore, String condition, String owner) {
        JSPolicyRepresentation rep = new JSPolicyRepresentation();

        rep.setName(KeycloakModelUtils.generateId());
        rep.setCode(condition);

        PolicyModel associatedPolicy = policyStore.create(rep, policy.getResourceServer());

        associatedPolicy.setOwner(owner);

        policy.addAssociatedPolicy(associatedPolicy);
    }

    private void createClientPolicy(PolicyModel policy, PolicyStore policyStore, String client, String owner) {
        ClientPolicyRepresentation rep = new ClientPolicyRepresentation();

        rep.setName(KeycloakModelUtils.generateId());
        rep.addClient(client);

        PolicyModel associatedPolicy = policyStore.create(rep, policy.getResourceServer());

        associatedPolicy.setOwner(owner);

        policy.addAssociatedPolicy(associatedPolicy);
    }

    private void createGroupPolicy(PolicyModel policy, PolicyStore policyStore, String group, String owner) {
        GroupPolicyRepresentation rep = new GroupPolicyRepresentation();

        rep.setName(KeycloakModelUtils.generateId());
        rep.addGroupPath(group);

        PolicyModel associatedPolicy = policyStore.create(rep, policy.getResourceServer());

        associatedPolicy.setOwner(owner);

        policy.addAssociatedPolicy(associatedPolicy);
    }

    private void createRolePolicy(PolicyModel policy, PolicyStore policyStore, String role, String owner) {
        RolePolicyRepresentation rep = new RolePolicyRepresentation();

        rep.setName(KeycloakModelUtils.generateId());
        rep.addRole(role, false);

        PolicyModel associatedPolicy = policyStore.create(rep, policy.getResourceServer());

        associatedPolicy.setOwner(owner);

        policy.addAssociatedPolicy(associatedPolicy);
    }

    private void createUserPolicy(PolicyModel policy, PolicyStore policyStore, String user, String owner) {
        UserPolicyRepresentation rep = new UserPolicyRepresentation();

        rep.setName(KeycloakModelUtils.generateId());
        rep.addUser(user);

        PolicyModel associatedPolicy = policyStore.create(rep, policy.getResourceServer());

        associatedPolicy.setOwner(owner);

        policy.addAssociatedPolicy(associatedPolicy);
    }
}
