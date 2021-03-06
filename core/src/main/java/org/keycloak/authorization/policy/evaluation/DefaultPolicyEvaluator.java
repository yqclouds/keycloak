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
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    @Override
    public void evaluate(ResourcePermission permission, AuthorizationProvider authorizationProvider, EvaluationContext executionContext, Decision decision, Map<PolicyModel, Map<Object, Decision.Effect>> decisionCache) {
        StoreFactory storeFactory = authorizationProvider.getStoreFactory();
        PolicyStore policyStore = storeFactory.getPolicyStore();
        ResourceStore resourceStore = storeFactory.getResourceStore();

        ResourceServerModel resourceServer = permission.getResourceServer();
        PolicyEnforcementMode enforcementMode = resourceServer.getPolicyEnforcementMode();

        if (PolicyEnforcementMode.DISABLED.equals(enforcementMode)) {
            DefaultEvaluation evaluation = new DefaultEvaluation(permission, executionContext, decision, authorizationProvider);

            evaluation.grant();

            decision.onComplete(permission);
            return;
        }

        AtomicBoolean verified = new AtomicBoolean();
        Consumer<PolicyModel> policyConsumer = createPolicyEvaluator(permission, authorizationProvider, executionContext, decision, verified, decisionCache);
        ResourceModel resource = permission.getResource();

        if (resource != null) {
            policyStore.findByResource(resource.getId(), resourceServer.getId(), policyConsumer);

            if (resource.getType() != null) {
                policyStore.findByResourceType(resource.getType(), resourceServer.getId(), policyConsumer);

                if (!resource.getOwner().equals(resourceServer.getId())) {
                    for (ResourceModel typedResource : resourceStore.findByType(resource.getType(), resourceServer.getId())) {
                        policyStore.findByResource(typedResource.getId(), resourceServer.getId(), policyConsumer);
                    }
                }
            }
        }

        List<ScopeModel> scopes = permission.getScopes();

        if (!scopes.isEmpty()) {
            policyStore.findByScopeIds(scopes.stream().map(ScopeModel::getId).collect(Collectors.toList()), null, resourceServer.getId(), policyConsumer);
        }

        if (verified.get()) {
            decision.onComplete(permission);
            return;
        }

        if (PolicyEnforcementMode.PERMISSIVE.equals(enforcementMode)) {
            DefaultEvaluation evaluation = new DefaultEvaluation(permission, executionContext, decision, authorizationProvider);
            evaluation.grant();
            decision.onComplete(permission);
        }
    }

    private Consumer<PolicyModel> createPolicyEvaluator(ResourcePermission permission, AuthorizationProvider authorizationProvider, EvaluationContext executionContext, Decision decision, AtomicBoolean verified, Map<PolicyModel, Map<Object, Decision.Effect>> decisionCache) {
        return parentPolicy -> {
            PolicyProvider policyProvider = authorizationProvider.getProvider(parentPolicy.getType());

            if (policyProvider == null) {
                throw new RuntimeException("Unknown parentPolicy provider for type [" + parentPolicy.getType() + "].");
            }

            policyProvider.evaluate(new DefaultEvaluation(permission, executionContext, parentPolicy, decision, authorizationProvider, decisionCache));

            verified.compareAndSet(false, true);
        };
    }
}
