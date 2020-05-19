/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

import org.keycloak.authorization.jpa.entities.PermissionTicket;
import org.keycloak.authorization.jpa.entities.Policy;
import org.keycloak.authorization.jpa.entities.ScopeEntity;
import org.keycloak.authorization.model.*;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.jpa.JpaModel;

import static org.keycloak.authorization.UserManagedPermissionUtil.updatePolicy;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PermissionTicketAdapter implements org.keycloak.authorization.model.PermissionTicket, JpaModel<PermissionTicket> {

    private final PermissionTicket entity;
    private final StoreFactory storeFactory;

    public PermissionTicketAdapter(PermissionTicket entity, StoreFactory storeFactory) {
        this.entity = entity;
        this.storeFactory = storeFactory;
    }

    public org.keycloak.authorization.jpa.entities.PermissionTicket toEntity(org.keycloak.authorization.model.PermissionTicket permission) {
        if (permission instanceof PermissionTicketAdapter) {
            return ((PermissionTicketAdapter) permission).getEntity();
        } else {
            return em.getReference(org.keycloak.authorization.jpa.entities.PermissionTicket.class, permission.getId());
        }
    }

    @Override
    public PermissionTicket getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public String getOwner() {
        return entity.getOwner();
    }

    @Override
    public String getRequester() {
        return entity.getRequester();
    }

    @Override
    public boolean isGranted() {
        return entity.isGranted();
    }

    @Override
    public Long getCreatedTimestamp() {
        return entity.getCreatedTimestamp();
    }

    @Override
    public Long getGrantedTimestamp() {
        return entity.getGrantedTimestamp();
    }

    @Override
    public void setGrantedTimestamp(Long millis) {
        entity.setGrantedTimestamp(millis);
        updatePolicy(this, storeFactory);
    }

    @Override
    public ResourceServer getResourceServer() {
        return storeFactory.getResourceServerStore().findById(entity.getResourceServer().getId());
    }

    @Override
    public org.keycloak.authorization.model.Policy getPolicy() {
        Policy policy = entity.getPolicy();

        if (policy == null) {
            return null;
        }

        return storeFactory.getPolicyStore().findById(policy.getId(), entity.getResourceServer().getId());
    }

    @Override
    public void setPolicy(org.keycloak.authorization.model.Policy policy) {
        if (policy != null) {
            entity.setPolicy(entityManager.getReference(Policy.class, policy.getId()));
        }
    }

    @Override
    public Resource getResource() {
        return storeFactory.getResourceStore().findById(entity.getResource().getId(), getResourceServer().getId());
    }

    @Override
    public Scope getScope() {
        ScopeEntity scope = entity.getScope();

        if (scope == null) {
            return null;
        }

        return storeFactory.getScopeStore().findById(scope.getId(), getResourceServer().getId());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof org.keycloak.authorization.model.Policy)) return false;

        org.keycloak.authorization.model.PermissionTicket that = (org.keycloak.authorization.model.PermissionTicket) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }


}
