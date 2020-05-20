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
package org.keycloak.authorization.jpa.store;

import com.hsbc.unified.iam.entity.authorization.ResourceServer;
import com.hsbc.unified.iam.repository.authorization.*;
import org.keycloak.authorization.AuthorizationProvider;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.models.ModelException;
import org.keycloak.storage.StorageId;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceServerStore implements ResourceServerStore {

    private final AuthorizationProvider provider;

    @Autowired
    private ResourceServerRepository resourceServerRepository;
    @Autowired
    private PolicyRepository policyRepository;
    @Autowired
    private PermissionTicketRepository permissionTicketRepository;
    @Autowired
    private ResourceRepository resourceRepository;
    @Autowired
    private ScopeRepository scopeRepository;

    public JPAResourceServerStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public ResourceServerModel create(String clientId) {
        if (!StorageId.isLocalStorage(clientId)) {
            throw new ModelException("Creating resource server from federated ClientModel not supported");
        }
        ResourceServer entity = new ResourceServer();

        entity.setId(clientId);

        resourceServerRepository.save(entity);

        return new ResourceServerAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        Optional<ResourceServer> optional = resourceServerRepository.findById(id);
        if (!optional.isPresent()) return;

        List<String> policyIds = policyRepository.findPolicyIdByServerId(id);
        for (String policyId : policyIds) {
            policyRepository.deleteById(policyId);
        }

        List<String> permissionIds = permissionTicketRepository.findPermissionTicketIdByServerId(id);
        for (String permissionId : permissionIds) {
            permissionTicketRepository.deleteById(permissionId);
        }

        List<String> resourceIds = resourceRepository.findResourceIdByServerId(id);
        for (String resourceId : resourceIds) {
            resourceRepository.deleteById(resourceId);
        }

        List<String> scopeIds = scopeRepository.findScopeIdByResourceServer(id);
        for (String scopeId : scopeIds) {
            scopeRepository.deleteById(scopeId);
        }

        resourceServerRepository.delete(optional.get());
    }

    @Override
    public ResourceServerModel findById(String id) {
        Optional<ResourceServer> optional = resourceServerRepository.findById(id);
        return optional.map(resourceServer -> new ResourceServerAdapter(resourceServer, provider.getStoreFactory()))
                .orElse(null);
    }
}
