/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.policy.evaluation;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.Decision;
import org.keycloak.authorization.Decision.Effect;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.idm.authorization.Logic;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultEvaluation implements Evaluation {
    private final ResourcePermission permission;
    private final EvaluationContext executionContext;
    private final Decision decision;
    private final PolicyModel parentPolicy;
    private final AuthorizationProvider authorizationProvider;
    private final Realm realm;
    private PolicyModel policy;
    private Map<PolicyModel, Map<Object, Effect>> decisionCache;
    private Effect effect;

    public DefaultEvaluation(ResourcePermission permission, EvaluationContext executionContext, PolicyModel parentPolicy, Decision decision, AuthorizationProvider authorizationProvider, Map<PolicyModel, Map<Object, Decision.Effect>> decisionCache) {
        this(permission, executionContext, parentPolicy, null, decision, authorizationProvider, decisionCache);
    }

    public DefaultEvaluation(ResourcePermission permission, EvaluationContext executionContext, Decision decision, AuthorizationProvider authorizationProvider) {
        this(permission, executionContext, null, null, decision, authorizationProvider, Collections.emptyMap());
    }

    public DefaultEvaluation(ResourcePermission permission, EvaluationContext executionContext, PolicyModel parentPolicy, PolicyModel policy, Decision decision, AuthorizationProvider authorizationProvider, Map<PolicyModel, Map<Object, Decision.Effect>> decisionCache) {
        this.permission = permission;
        this.executionContext = executionContext;
        this.parentPolicy = parentPolicy;
        this.policy = policy;
        this.decision = decision;
        this.authorizationProvider = authorizationProvider;
        this.decisionCache = decisionCache;
        this.realm = createRealm();
    }

    @Override
    public ResourcePermission getPermission() {
        return this.permission;
    }

    @Override
    public EvaluationContext getContext() {
        return this.executionContext;
    }

    @Override
    public void grant() {
        if (policy != null && Logic.NEGATIVE.equals(policy.getLogic())) {
            setEffect(Effect.DENY);
        } else {
            setEffect(Effect.PERMIT);
        }
    }

    @Override
    public void deny() {
        if (policy != null && Logic.NEGATIVE.equals(policy.getLogic())) {
            setEffect(Effect.PERMIT);
        } else {
            setEffect(Effect.DENY);
        }
    }

    @Override
    public PolicyModel getPolicy() {
        if (policy == null) {
            return parentPolicy;
        }
        return this.policy;
    }

    public void setPolicy(PolicyModel policy) {
        this.policy = policy;
        this.effect = null;
    }

    @Override
    public Realm getRealm() {
        return realm;
    }

    @Override
    public AuthorizationProvider getAuthorizationProvider() {
        return authorizationProvider;
    }

    public PolicyModel getParentPolicy() {
        return this.parentPolicy;
    }

    public Effect getEffect() {
        return effect;
    }

    public void setEffect(Effect effect) {
        this.effect = effect;
        this.decision.onDecision(this);
    }

    public Map<PolicyModel, Map<Object, Effect>> getDecisionCache() {
        return decisionCache;
    }

    @Override
    public void denyIfNoEffect() {
        if (this.effect == null) {
            deny();
        }
    }

    private Realm createRealm() {
        return new Realm() {

            @Override
            public boolean isUserInGroup(String id, String groupId, boolean checkParent) {
                KeycloakSession session = authorizationProvider.getSession();
                UserModel user = getUser(id, session);

                if (Objects.isNull(user)) {
                    return false;
                }

                RealmModel realm = session.getContext().getRealm();
                GroupModel group = KeycloakModelUtils.findGroupByPath(realm, groupId);

                if (Objects.isNull(group)) {
                    return false;
                }

                if (checkParent) {
                    return RoleUtils.isMember(user.getGroups(), group);
                }

                return user.isMemberOf(group);
            }

            private UserModel getUser(String id, KeycloakSession session) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(id, realm);

                if (Objects.isNull(user)) {
                    user = session.users().getUserByUsername(id, realm);
                }
                if (Objects.isNull(user)) {
                    user = session.users().getUserByEmail(id, realm);
                }
                if (Objects.isNull(user)) {
                    user = session.users().getServiceAccount(realm.getClientById(id));
                }

                return user;
            }

            @Override
            public boolean isUserInRealmRole(String id, String roleName) {
                KeycloakSession session = authorizationProvider.getSession();
                UserModel user = getUser(id, session);

                if (Objects.isNull(user)) {
                    return false;
                }

                Set<RoleModel> roleMappings = user.getRoleMappings().stream()
                        .filter(role -> !role.isClientRole())
                        .collect(Collectors.toSet());

                return RoleUtils.hasRole(roleMappings, session.getContext().getRealm().getRole(roleName));
            }

            @Override
            public boolean isUserInClientRole(String id, String clientId, String roleName) {
                KeycloakSession session = authorizationProvider.getSession();
                RealmModel realm = session.getContext().getRealm();
                UserModel user = getUser(id, session);

                if (Objects.isNull(user)) {
                    return false;
                }

                Set<RoleModel> roleMappings = user.getRoleMappings().stream()
                        .filter(role -> role.isClientRole() && ClientModel.class.cast(role.getContainer()).getClientId().equals(clientId))
                        .collect(Collectors.toSet());

                if (roleMappings.isEmpty()) {
                    return false;
                }

                RoleModel role = realm.getClientById(ClientModel.class.cast(roleMappings.iterator().next().getContainer()).getId()).getRole(roleName);

                if (Objects.isNull(role)) {
                    return false;
                }

                return RoleUtils.hasRole(roleMappings, role);
            }

            @Override
            public boolean isGroupInRole(String id, String role) {
                KeycloakSession session = authorizationProvider.getSession();
                RealmModel realm = session.getContext().getRealm();
                GroupModel group = KeycloakModelUtils.findGroupByPath(realm, id);

                return RoleUtils.hasRoleFromGroup(group, realm.getRole(role), false);
            }

            @Override
            public List<String> getUserRealmRoles(String id) {
                return getUser(id, authorizationProvider.getSession()).getRoleMappings().stream()
                        .filter(role -> !role.isClientRole())
                        .map(RoleModel::getName)
                        .collect(Collectors.toList());
            }

            @Override
            public List<String> getUserClientRoles(String id, String clientId) {
                return getUser(id, authorizationProvider.getSession()).getRoleMappings().stream()
                        .filter(role -> role.isClientRole())
                        .map(RoleModel::getName)
                        .collect(Collectors.toList());
            }

            @Override
            public List<String> getUserGroups(String id) {
                return getUser(id, authorizationProvider.getSession()).getGroups().stream()
                        .map(ModelToRepresentation::buildGroupPath)
                        .collect(Collectors.toList());
            }

            @Override
            public Map<String, List<String>> getUserAttributes(String id) {
                return Collections.unmodifiableMap(getUser(id, authorizationProvider.getSession()).getAttributes());
            }
        };
    }
}
