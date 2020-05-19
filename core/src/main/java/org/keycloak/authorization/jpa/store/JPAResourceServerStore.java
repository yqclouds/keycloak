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

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.jpa.entities.*;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.models.ModelException;
import org.keycloak.storage.StorageId;

import javax.persistence.TypedQuery;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceServerStore implements ResourceServerStore {

    private final AuthorizationProvider provider;

    public JPAResourceServerStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public org.keycloak.authorization.model.ResourceServer create(String clientId) {
        if (!StorageId.isLocalStorage(clientId)) {
            throw new ModelException("Creating resource server from federated ClientModel not supported");
        }
        ResourceServer entity = new ResourceServer();

        entity.setId(clientId);

        this.entityManager.persist(entity);

        return new ResourceServerAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        ResourceServer entity = entityManager.find(ResourceServer.class, id);
        if (entity == null) return;
        //This didn't work, had to loop through and remove each policy individually
        //entityManager.createNamedQuery("deletePolicyByResourceServer")
        //        .setParameter("serverId", id).executeUpdate();

        {
            TypedQuery<String> query = entityManager.createNamedQuery("findPolicyIdByServerId", String.class);
            query.setParameter("serverId", id);
            List<String> result = query.getResultList();
            for (String policyId : result) {
                entityManager.remove(entityManager.getReference(Policy.class, policyId));
            }
        }

        {
            TypedQuery<String> query = entityManager.createNamedQuery("findPermissionTicketIdByServerId", String.class);

            query.setParameter("serverId", id);

            List<String> result = query.getResultList();
            for (String permissionId : result) {
                entityManager.remove(entityManager.getReference(PermissionTicket.class, permissionId));
            }
        }

        //entityManager.createNamedQuery("deleteResourceByResourceServer")
        //        .setParameter("serverId", id).executeUpdate();
        {
            TypedQuery<String> query = entityManager.createNamedQuery("findResourceIdByServerId", String.class);

            query.setParameter("serverId", id);

            List<String> result = query.getResultList();
            for (String resourceId : result) {
                entityManager.remove(entityManager.getReference(Resource.class, resourceId));
            }
        }

        //entityManager.createNamedQuery("deleteScopeByResourceServer")
        //        .setParameter("serverId", id).executeUpdate();
        {
            TypedQuery<String> query = entityManager.createNamedQuery("findScopeIdByResourceServer", String.class);

            query.setParameter("serverId", id);

            List<String> result = query.getResultList();
            for (String scopeId : result) {
                entityManager.remove(entityManager.getReference(ScopeEntity.class, scopeId));
            }
        }

        this.entityManager.remove(entity);
        entityManager.flush();
        entityManager.detach(entity);
    }

    @Override
    public org.keycloak.authorization.model.ResourceServer findById(String id) {
        ResourceServer entity = entityManager.find(ResourceServer.class, id);
        if (entity == null) return null;
        return new ResourceServerAdapter(entity, provider.getStoreFactory());
    }
}
