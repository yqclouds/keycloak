/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.keycloak.authorization.policy.provider.aggregated;

import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.representations.idm.authorization.AggregatePolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component("AggregatePolicyProviderFactory")
@ProviderFactory(id = "aggregate", providerClasses = PolicyProvider.class)
public class AggregatePolicyProviderFactory implements PolicyProviderFactory<AggregatePolicyRepresentation> {

    private AggregatePolicyProvider provider = new AggregatePolicyProvider();

    @Override
    public String getName() {
        return "Aggregated";
    }

    @Override
    public String getGroup() {
        return "Others";
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return provider;
    }

    @Override
    public PolicyProvider create() {
        return null;
    }

    @Override
    public void onCreate(PolicyModel policy, AggregatePolicyRepresentation representation, AuthorizationProvider authorization) {
        verifyCircularReference(policy, new ArrayList<>());
    }

    @Override
    public void onUpdate(PolicyModel policy, AggregatePolicyRepresentation representation, AuthorizationProvider authorization) {
        verifyCircularReference(policy, new ArrayList<>());
    }

    @Override
    public void onImport(PolicyModel policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        verifyCircularReference(policy, new ArrayList<>());
    }

    @Override
    public AggregatePolicyRepresentation toRepresentation(PolicyModel policy, AuthorizationProvider authorization) {
        return new AggregatePolicyRepresentation();
    }

    @Override
    public Class<AggregatePolicyRepresentation> getRepresentationType() {
        return AggregatePolicyRepresentation.class;
    }

    private void verifyCircularReference(PolicyModel policy, List<String> ids) {
        if (!policy.getType().equals("aggregate")) {
            return;
        }

        if (ids.contains(policy.getId())) {
            throw new RuntimeException("Circular reference found [" + policy.getName() + "].");
        }

        ids.add(policy.getId());

        for (PolicyModel associated : policy.getAssociatedPolicies()) {
            verifyCircularReference(associated, ids);
        }
    }

    @Override
    public void onRemove(PolicyModel policy, AuthorizationProvider authorization) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "aggregate";
    }
}
