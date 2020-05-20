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
package org.keycloak.authorization.jpa.store;

import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import org.keycloak.authorization.jpa.entities.*;
import org.keycloak.authorization.model.AbstractAuthorizationModel;
import org.keycloak.authorization.model.ResourceModel;
import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.authorization.model.ScopeModel;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.jpa.JpaModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.EntityManagerFactory;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ResourceAdapter extends AbstractAuthorizationModel implements ResourceModel, JpaModel<Resource> {

    private final Resource entity;
    private final StoreFactory storeFactory;

    @Autowired
    private ResourceRepository resourceRepository;
    @Autowired
    private ResourceAttributeRepository resourceAttributeRepository;
    @Autowired
    private ScopeRepository scopeRepository;

    @Autowired
    private EntityManagerFactory emf;

    public ResourceAdapter(Resource entity, StoreFactory storeFactory) {
        super(storeFactory);
        this.entity = entity;
        this.storeFactory = storeFactory;
    }

    public Resource toEntity(ResourceModel resource) {
        if (resource instanceof ResourceAdapter) {
            return ((ResourceAdapter) resource).getEntity();
        } else {
            return resourceRepository.getOne(resource.getId());
        }
    }

    @Override
    public Resource getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public String getName() {
        return entity.getName();
    }

    @Override
    public void setName(String name) {
        throwExceptionIfReadonly();
        entity.setName(name);

    }

    @Override
    public String getDisplayName() {
        return entity.getDisplayName();
    }

    @Override
    public void setDisplayName(String name) {
        throwExceptionIfReadonly();
        entity.setDisplayName(name);
    }

    @Override
    public Set<String> getUris() {
        return entity.getUris();
    }

    @Override
    public void updateUris(Set<String> uri) {
        throwExceptionIfReadonly();
        entity.setUris(uri);
    }

    @Override
    public String getType() {
        return entity.getType();
    }

    @Override
    public void setType(String type) {
        throwExceptionIfReadonly();
        entity.setType(type);

    }

    @Override
    public List<ScopeModel> getScopes() {
        List<ScopeModel> scopes = new LinkedList<>();
        for (Scope scope : entity.getScopes()) {
            scopes.add(storeFactory.getScopeStore().findById(scope.getId(), entity.getResourceServer().getId()));
        }

        return Collections.unmodifiableList(scopes);
    }

    @Override
    public String getIconUri() {
        return entity.getIconUri();
    }

    @Override
    public void setIconUri(String iconUri) {
        throwExceptionIfReadonly();
        entity.setIconUri(iconUri);

    }

    @Override
    public ResourceServerModel getResourceServer() {
        return storeFactory.getResourceServerStore().findById(entity.getResourceServer().getId());
    }

    @Override
    public String getOwner() {
        return entity.getOwner();
    }

    @Override
    public boolean isOwnerManagedAccess() {
        return entity.isOwnerManagedAccess();
    }

    @Override
    public void setOwnerManagedAccess(boolean ownerManagedAccess) {
        throwExceptionIfReadonly();
        entity.setOwnerManagedAccess(ownerManagedAccess);
    }

    @Override
    public void updateScopes(Set<ScopeModel> toUpdate) {
        throwExceptionIfReadonly();
        Set<String> ids = new HashSet<>();
        for (ScopeModel scope : toUpdate) {
            ids.add(scope.getId());
        }
        Iterator<Scope> it = entity.getScopes().iterator();
        while (it.hasNext()) {
            Scope next = it.next();
            if (!ids.contains(next.getId())) it.remove();
            else ids.remove(next.getId());
        }
        for (String addId : ids) {
            entity.getScopes().add(scopeRepository.getOne(addId));
        }
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> result = new MultivaluedHashMap<>();
        for (ResourceAttribute attr : entity.getAttributes()) {
            result.add(attr.getName(), attr.getValue());
        }
        return Collections.unmodifiableMap(result);
    }

    @Override
    public String getSingleAttribute(String name) {
        List<String> values = getAttributes().getOrDefault(name, Collections.emptyList());

        if (values.isEmpty()) {
            return null;
        }

        return values.get(0);
    }

    @Override
    public List<String> getAttribute(String name) {
        List<String> values = getAttributes().getOrDefault(name, Collections.emptyList());

        if (values.isEmpty()) {
            return null;
        }

        return Collections.unmodifiableList(values);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        removeAttribute(name);

        for (String value : values) {
            ResourceAttribute attr = new ResourceAttribute();
            attr.setId(KeycloakModelUtils.generateId());
            attr.setName(name);
            attr.setValue(value);
            attr.setResource(entity);
            resourceAttributeRepository.save(attr);
            entity.getAttributes().add(attr);
        }
    }

    @Override
    public void removeAttribute(String name) {
        throwExceptionIfReadonly();

        resourceAttributeRepository.deleteResourceAttributesByNameAndResource(name, entity.getId());

        List<ResourceAttribute> toRemove = new ArrayList<>();

        for (ResourceAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                toRemove.add(attr);
            }
        }

        entity.getAttributes().removeAll(toRemove);
    }

    @Override
    public boolean isFetched(String association) {
        return emf.getPersistenceUnitUtil().isLoaded(this, association);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResourceModel)) return false;

        ResourceModel that = (ResourceModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
