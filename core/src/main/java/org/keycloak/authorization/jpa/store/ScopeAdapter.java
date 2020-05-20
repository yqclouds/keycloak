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

import org.keycloak.authorization.jpa.entities.Scope;
import org.keycloak.authorization.jpa.entities.ScopeRepository;
import org.keycloak.authorization.model.AbstractAuthorizationModel;
import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.authorization.model.ScopeModel;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.jpa.JpaModel;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ScopeAdapter extends AbstractAuthorizationModel implements ScopeModel, JpaModel<Scope> {
    private final Scope entity;
    private final StoreFactory storeFactory;

    @Autowired
    private ScopeRepository scopeRepository;

    public ScopeAdapter(Scope entity, StoreFactory storeFactory) {
        super(storeFactory);
        this.entity = entity;
        this.storeFactory = storeFactory;
    }

    public Scope toEntity(ScopeModel scope) {
        if (scope instanceof ScopeAdapter) {
            return ((ScopeAdapter) scope).getEntity();
        } else {
            return scopeRepository.getOne(scope.getId());
        }
    }

    @Override
    public Scope getEntity() {
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ScopeModel)) return false;

        ScopeModel that = (ScopeModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

}
