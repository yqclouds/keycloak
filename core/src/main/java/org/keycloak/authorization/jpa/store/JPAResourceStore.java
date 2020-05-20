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
import com.hsbc.unified.iam.entity.authorization.Resource;
import com.hsbc.unified.iam.repository.authorization.ResourceRepository;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.NoResultException;
import javax.persistence.criteria.Expression;
import javax.persistence.criteria.Predicate;
import java.util.*;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceStore implements ResourceStore {

    private final AuthorizationProvider provider;

    @Autowired
    private ResourceServerAdapter resourceServerAdapter;

    @Autowired
    private ResourceRepository resourceRepository;

    public JPAResourceStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public ResourceModel create(String name, ResourceServerModel resourceServer, String owner) {
        return create(null, name, resourceServer, owner);
    }

    @Override
    public ResourceModel create(String id, String name, ResourceServerModel resourceServer, String owner) {
        Resource entity = new Resource();

        if (id == null) {
            entity.setId(KeycloakModelUtils.generateId());
        } else {
            entity.setId(id);
        }

        entity.setName(name);
        entity.setResourceServer(resourceServerAdapter.toEntity(resourceServer));
        entity.setOwner(owner);
        resourceRepository.save(entity);

        return new ResourceAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        Optional<Resource> optional = resourceRepository.findById(id);
        if (!optional.isPresent()) return;

        optional.get().getScopes().clear();
        resourceRepository.delete(optional.get());
    }

    @Override
    public ResourceModel findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        Optional<Resource> optional = resourceRepository.findById(id);
        return optional.map(resource -> new ResourceAdapter(resource, provider.getStoreFactory())).orElse(null);
    }

    @Override
    public List<ResourceModel> findByOwner(String ownerId, String resourceServerId) {
        List<ResourceModel> list = new LinkedList<>();

        findByOwner(ownerId, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByOwner(String ownerId, String resourceServerId, Consumer<ResourceModel> consumer) {
        findByOwnerFilter(ownerId, resourceServerId, consumer, -1, -1);
    }

    @Override
    public List<ResourceModel> findByOwner(String ownerId, String resourceServerId, int first, int max) {
        List<ResourceModel> list = new LinkedList<>();

        findByOwnerFilter(ownerId, resourceServerId, list::add, first, max);

        return list;
    }

    private void findByOwnerFilter(String ownerId, String resourceServerId, Consumer<ResourceModel> consumer, int firstResult, int maxResult) {
        List<Resource> result;

        boolean pagination = firstResult > -1 && maxResult > -1;
        if (resourceServerId == null) {
            if (pagination) {
                result = resourceRepository.findAnyResourceIdByOwnerOrdered(ownerId);
            } else {
                result = resourceRepository.findAnyResourceIdByOwner(ownerId);
            }
        } else {
            if (pagination) {
                result = resourceRepository.findResourceIdByOwnerOrdered(resourceServerId, ownerId);
            } else {
                result = resourceRepository.findResourceIdByOwner(resourceServerId, ownerId);
            }
        }

        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();
        for (Resource entity : result) {
            ResourceModel cached = resourceStore.findById(entity.getId(), resourceServerId);

            if (cached != null) {
                consumer.accept(cached);
            }
        }
    }

    @Override
    public List<ResourceModel> findByUri(String uri, String resourceServerId) {
        List<String> result = resourceRepository.findResourceIdByUri(uri, resourceServerId);
        List<ResourceModel> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            ResourceModel resource = resourceStore.findById(id, resourceServerId);

            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<ResourceModel> findByResourceServer(String resourceServerId) {
        List<String> result = resourceRepository.findResourceIdByServerId(resourceServerId);
        List<ResourceModel> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            ResourceModel resource = resourceStore.findById(id, resourceServerId);

            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    private Specification<Resource> findByResourceServerSpecification(Map<String, String[]> attributes, String resourceServerId) {
        return (Specification<Resource>) (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (resourceServerId != null) {
                predicates.add(cb.equal(root.get("resourceServer").get("id"), resourceServerId));
            }

            attributes.forEach((name, value) -> {
                if ("id".equals(name)) {
                    predicates.add(root.get(name).in((Object) value));
                } else if ("scope".equals(name)) {
                    predicates.add(root.join("scopes").get("id").in((Object) value));
                } else if ("ownerManagedAccess".equals(name) && value.length > 0) {
                    predicates.add(cb.equal(root.get(name), Boolean.valueOf(value[0])));
                } else if ("uri".equals(name) && value.length > 0 && value[0] != null) {
                    predicates.add(cb.lower(root.join("uris")).in(value[0].toLowerCase()));
                } else if ("uri_not_null".equals(name)) {
                    // predicates.add(builder.isNotEmpty(root.get("uris"))); looks like there is a bug in hibernate and this line doesn't work: https://hibernate.atlassian.net/browse/HHH-6686
                    // Workaround
                    Expression<Integer> urisSize = cb.size(root.get("uris"));
                    predicates.add(cb.notEqual(urisSize, 0));
                } else if ("owner".equals(name)) {
                    predicates.add(root.get(name).in((Object) value));
                } else if (!ResourceModel.EXACT_NAME.equals(name)) {
                    if ("name".equals(name) && attributes.containsKey(ResourceModel.EXACT_NAME) && Boolean.parseBoolean(attributes.get(ResourceModel.EXACT_NAME)[0])
                            && value.length > 0 && value[0] != null) {
                        predicates.add(cb.equal(cb.lower(root.get(name)), value[0].toLowerCase()));
                    } else if (value.length > 0 && value[0] != null) {
                        predicates.add(cb.like(cb.lower(root.get(name)), "%" + value[0].toLowerCase() + "%"));
                    }
                }
            });

            criteriaQuery.where(predicates.toArray(new Predicate[0])).orderBy(cb.asc(root.get("name")));

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    public List<ResourceModel> findByResourceServer(Map<String, String[]> attributes, String resourceServerId, int firstResult, int maxResult) {
        List<Resource> result = resourceRepository.findAll(findByResourceServerSpecification(attributes, resourceServerId));
        List<ResourceModel> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (Resource res : result) {
            ResourceModel resource = resourceStore.findById(res.getId(), resourceServerId);
            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<ResourceModel> findByScope(List<String> scopes, String resourceServerId) {
        List<ResourceModel> result = new ArrayList<>();

        findByScope(scopes, resourceServerId, result::add);

        return result;
    }

    @Override
    public void findByScope(List<String> scopes, String resourceServerId, Consumer<ResourceModel> consumer) {
        StoreFactory storeFactory = provider.getStoreFactory();

        resourceRepository.findResourceIdByScope(scopes, resourceServerId).stream()
                .map(id -> new ResourceAdapter(id, storeFactory))
                .forEach(consumer);
    }

    @Override
    public ResourceModel findByName(String name, String resourceServerId) {
        return findByName(name, resourceServerId, resourceServerId);
    }

    @Override
    public ResourceModel findByName(String name, String ownerId, String resourceServerId) {
        try {
            return new ResourceAdapter(resourceRepository.findResourceIdByName(resourceServerId, name, ownerId),
                    provider.getStoreFactory());
        } catch (NoResultException ex) {
            return null;
        }
    }

    @Override
    public List<ResourceModel> findByType(String type, String resourceServerId) {
        List<ResourceModel> list = new LinkedList<>();

        findByType(type, resourceServerId, list::add);

        return list;
    }

    @Override
    public List<ResourceModel> findByType(String type, String owner, String resourceServerId) {
        List<ResourceModel> list = new LinkedList<>();

        findByType(type, owner, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByType(String type, String resourceServerId, Consumer<ResourceModel> consumer) {
        findByType(type, resourceServerId, resourceServerId, consumer);
    }

    @Override
    public void findByType(String type, String owner, String resourceServerId, Consumer<ResourceModel> consumer) {
        List<Resource> result;
        if (owner != null) {
            result = resourceRepository.findResourceIdByType(type);
        } else {
            result = resourceRepository.findResourceIdByTypeNoOwner(type, resourceServerId);
        }

        StoreFactory storeFactory = provider.getStoreFactory();
        result.stream().map(entity -> new ResourceAdapter(entity, storeFactory))
                .forEach(consumer);
    }

    @Override
    public List<ResourceModel> findByTypeInstance(String type, String resourceServerId) {
        List<ResourceModel> list = new LinkedList<>();

        findByTypeInstance(type, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByTypeInstance(String type, String resourceServerId, Consumer<ResourceModel> consumer) {
        StoreFactory storeFactory = provider.getStoreFactory();

        resourceRepository.findResourceIdByTypeInstance(type, resourceServerId).stream()
                .map(entity -> new ResourceAdapter(entity, storeFactory))
                .forEach(consumer);
    }
}
