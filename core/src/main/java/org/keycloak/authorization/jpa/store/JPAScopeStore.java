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
import com.hsbc.unified.iam.entity.authorization.Scope;
import com.hsbc.unified.iam.repository.authorization.ScopeRepository;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.NoResultException;
import javax.persistence.criteria.Predicate;
import java.util.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAScopeStore implements ScopeStore {

    private final AuthorizationProvider provider;
    @Autowired
    private ResourceServerAdapter resourceServerAdapter;

    @Autowired
    private ScopeRepository scopeRepository;

    public JPAScopeStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public ScopeModel create(final String name, final ResourceServerModel resourceServer) {
        return create(null, name, resourceServer);
    }

    @Override
    public ScopeModel create(String id, final String name, final ResourceServerModel resourceServer) {
        Scope entity = new Scope();

        if (id == null) {
            entity.setId(KeycloakModelUtils.generateId());
        } else {
            entity.setId(id);
        }

        entity.setName(name);
        entity.setResourceServer(resourceServerAdapter.toEntity(resourceServer));
        scopeRepository.save(entity);

        return new ScopeAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        scopeRepository.deleteById(id);
    }

    @Override
    public ScopeModel findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        Optional<Scope> optional = scopeRepository.findById(id);
        return optional.map(scope -> new ScopeAdapter(scope, provider.getStoreFactory())).orElse(null);
    }

    @Override
    public ScopeModel findByName(String name, String resourceServerId) {
        try {
            String id = scopeRepository.findScopeIdByName(resourceServerId, name);
            return provider.getStoreFactory().getScopeStore().findById(id, resourceServerId);
        } catch (NoResultException nre) {
            return null;
        }
    }

    @Override
    public List<ScopeModel> findByResourceServer(final String serverId) {
        List<String> result = scopeRepository.findScopeIdByResourceServer(serverId);
        List<ScopeModel> list = new LinkedList<>();
        for (String id : result) {
            list.add(provider.getStoreFactory().getScopeStore().findById(id, serverId));
        }
        return list;
    }

    private Specification<Scope> findByResourceServerSpecification(Map<String, String[]> attributes, String resourceServerId) {
        return (Specification<Scope>) (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("resourceServer").get("id"), resourceServerId));

            attributes.forEach((name, value) -> {
                if ("id".equals(name)) {
                    predicates.add(root.get(name).in((Object) value));
                } else {
                    predicates.add(cb.like(cb.lower(root.get(name)), "%" + value[0].toLowerCase() + "%"));
                }
            });

            criteriaQuery.where(predicates.toArray(new Predicate[0])).orderBy(cb.asc(root.get("name")));

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    public List<ScopeModel> findByResourceServer(Map<String, String[]> attributes, String resourceServerId, int firstResult, int maxResult) {
        List<Scope> result = scopeRepository.findAll(findByResourceServerSpecification(attributes, resourceServerId));
        List<ScopeModel> list = new LinkedList<>();
        for (Scope entity : result) {
            list.add(provider.getStoreFactory().getScopeStore().findById(entity.getId(), resourceServerId));
        }
        return list;
    }
}
