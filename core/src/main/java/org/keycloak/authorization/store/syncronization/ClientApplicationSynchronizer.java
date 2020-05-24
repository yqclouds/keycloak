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

package org.keycloak.authorization.store.syncronization;

import com.hsbc.unified.iam.entity.events.ClientRemovedEvent;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClientApplicationSynchronizer implements Synchronizer<ClientRemovedEvent> {
    @Autowired
    private AuthorizationProvider authorizationProvider;

    @Override
    public void synchronize(ClientRemovedEvent event) {
        removeFromClientPolicies(event);
    }

    private void removeFromClientPolicies(ClientRemovedEvent event) {
        StoreFactory storeFactory = authorizationProvider.getStoreFactory();
        ResourceServerStore store = storeFactory.getResourceServerStore();
        ResourceServerModel resourceServer = store.findById(((ClientModel) event.getSource()).getId());

        if (resourceServer != null) {
            storeFactory.getResourceServerStore().delete(resourceServer.getId());
        }

        Map<String, String[]> attributes = new HashMap<>();

        attributes.put("type", new String[]{"client"});
        attributes.put("config:clients", new String[]{((ClientModel) event.getSource()).getId()});

        List<PolicyModel> search = storeFactory.getPolicyStore().findByResourceServer(attributes, null, -1, -1);

        for (PolicyModel policy : search) {
            PolicyProviderFactory policyFactory = authorizationProvider.getProviderFactory(policy.getType());
            ClientPolicyRepresentation representation = ClientPolicyRepresentation.class.cast(policyFactory.toRepresentation(policy, authorizationProvider));
            Set<String> clients = representation.getClients();

            clients.remove(((ClientModel) event.getSource()).getId());

            if (clients.isEmpty()) {
                policyFactory.onRemove(policy, authorizationProvider);
                authorizationProvider.getStoreFactory().getPolicyStore().delete(policy.getId());
            } else {
                policyFactory.onUpdate(policy, representation, authorizationProvider);
            }
        }
    }
}
