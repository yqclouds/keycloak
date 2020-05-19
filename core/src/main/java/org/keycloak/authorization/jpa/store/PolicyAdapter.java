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

import org.keycloak.authorization.jpa.entities.Policy;
import org.keycloak.authorization.jpa.entities.ScopeEntity;
import org.keycloak.authorization.model.*;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.jpa.JpaModel;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PolicyAdapter extends AbstractAuthorizationModel implements org.keycloak.authorization.model.Policy, JpaModel<Policy> {
    private Policy entity;
    private StoreFactory storeFactory;

    @Autowired
    private ResourceAdapter resourceAdapter;

    public PolicyAdapter(Policy entity, StoreFactory storeFactory) {
        super(storeFactory);
        this.entity = entity;
        this.storeFactory = storeFactory;
    }

    public Policy toEntity(org.keycloak.authorization.model.Policy policy) {
        if (policy instanceof PolicyAdapter) {
            return ((PolicyAdapter) policy).getEntity();
        } else {
            return em.getReference(Policy.class, policy.getId());
        }
    }

    @Override
    public Policy getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public String getType() {
        return entity.getType();
    }

    @Override
    public DecisionStrategy getDecisionStrategy() {
        return entity.getDecisionStrategy();
    }

    @Override
    public void setDecisionStrategy(DecisionStrategy decisionStrategy) {
        throwExceptionIfReadonly();
        entity.setDecisionStrategy(decisionStrategy);

    }

    @Override
    public Logic getLogic() {
        return entity.getLogic();
    }

    @Override
    public void setLogic(Logic logic) {
        throwExceptionIfReadonly();
        entity.setLogic(logic);
    }

    @Override
    public Map<String, String> getConfig() {
        Map<String, String> result = new HashMap<String, String>();
        if (entity.getConfig() != null) result.putAll(entity.getConfig());
        return Collections.unmodifiableMap(result);
    }

    @Override
    public void setConfig(Map<String, String> config) {
        throwExceptionIfReadonly();
        if (entity.getConfig() == null) {
            entity.setConfig(new HashMap<>());
        } else {
            entity.getConfig().clear();
        }
        entity.getConfig().putAll(config);
    }

    @Override
    public void removeConfig(String name) {
        throwExceptionIfReadonly();
        if (entity.getConfig() == null) {
            return;
        }
        entity.getConfig().remove(name);
    }

    @Override
    public void putConfig(String name, String value) {
        throwExceptionIfReadonly();
        if (entity.getConfig() == null) {
            entity.setConfig(new HashMap<>());
        }
        entity.getConfig().put(name, value);

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
    public String getDescription() {
        return entity.getDescription();
    }

    @Override
    public void setDescription(String description) {
        throwExceptionIfReadonly();
        entity.setDescription(description);

    }

    @Override
    public ResourceServer getResourceServer() {
        return storeFactory.getResourceServerStore().findById(entity.getResourceServer().getId());
    }

    @Override
    public Set<org.keycloak.authorization.model.Policy> getAssociatedPolicies() {
        Set<org.keycloak.authorization.model.Policy> result = new HashSet<>();
        for (Policy policy : entity.getAssociatedPolicies()) {
            result.add(new PolicyAdapter(policy, storeFactory));
        }
        return Collections.unmodifiableSet(result);
    }

    @Override
    public Set<org.keycloak.authorization.model.Resource> getResources() {
        Set<org.keycloak.authorization.model.Resource> set = new HashSet<>();
        for (org.keycloak.authorization.jpa.entities.Resource res : entity.getResources()) {
            set.add(storeFactory.getResourceStore().findById(res.getId(), entity.getResourceServer().getId()));
        }
        return Collections.unmodifiableSet(set);
    }

    @Override
    public Set<Scope> getScopes() {
        Set<Scope> set = new HashSet<>();
        for (ScopeEntity res : entity.getScopes()) {
            set.add(storeFactory.getScopeStore().findById(res.getId(), entity.getResourceServer().getId()));
        }
        return Collections.unmodifiableSet(set);
    }

    @Override
    public void addScope(Scope scope) {
        throwExceptionIfReadonly();
        entity.getScopes().add(ScopeAdapter.toEntity(em, scope));
    }

    @Override
    public void removeScope(Scope scope) {
        throwExceptionIfReadonly();
        entity.getScopes().remove(ScopeAdapter.toEntity(em, scope));

    }

    @Override
    public void addAssociatedPolicy(org.keycloak.authorization.model.Policy associatedPolicy) {
        throwExceptionIfReadonly();
        entity.getAssociatedPolicies().add(toEntity(associatedPolicy));
    }

    @Override
    public void removeAssociatedPolicy(org.keycloak.authorization.model.Policy associatedPolicy) {
        throwExceptionIfReadonly();
        entity.getAssociatedPolicies().remove(toEntity(associatedPolicy));

    }

    @Override
    public void addResource(org.keycloak.authorization.model.Resource resource) {
        throwExceptionIfReadonly();
        entity.getResources().add(resourceAdapter.toEntity(resource));
    }

    @Override
    public void removeResource(org.keycloak.authorization.model.Resource resource) {
        throwExceptionIfReadonly();
        entity.getResources().remove(resourceAdapter.toEntity(resource));
    }

    @Override
    public String getOwner() {
        return entity.getOwner();
    }

    @Override
    public void setOwner(String owner) {
        throwExceptionIfReadonly();
        entity.setOwner(owner);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof org.keycloak.authorization.model.Policy)) return false;

        org.keycloak.authorization.model.Policy that = (org.keycloak.authorization.model.Policy) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    @Override
    public boolean isFetched(String association) {
        return em.getEntityManagerFactory().getPersistenceUnitUtil().isLoaded(entity, association);
    }
}
