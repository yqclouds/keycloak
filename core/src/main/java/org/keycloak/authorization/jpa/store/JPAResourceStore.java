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
import org.keycloak.authorization.jpa.entities.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.*;
import javax.persistence.criteria.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceStore implements ResourceStore {

    private final AuthorizationProvider provider;

    @Autowired
    private ResourceServerAdapter resourceServerAdapter;

    public JPAResourceStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public org.keycloak.authorization.model.Resource create(String name, ResourceServer resourceServer, String owner) {
        return create(null, name, resourceServer, owner);
    }

    @Override
    public org.keycloak.authorization.model.Resource create(String id, String name, ResourceServer resourceServer, String owner) {
        Resource entity = new Resource();

        if (id == null) {
            entity.setId(KeycloakModelUtils.generateId());
        } else {
            entity.setId(id);
        }

        entity.setName(name);
        entity.setResourceServer(resourceServerAdapter.toEntity(resourceServer));
        entity.setOwner(owner);

        this.entityManager.persist(entity);
        this.entityManager.flush();

        return new ResourceAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        Resource resource = entityManager.getReference(Resource.class, id);
        if (resource == null) return;

        resource.getScopes().clear();
        this.entityManager.remove(resource);
    }

    @Override
    public org.keycloak.authorization.model.Resource findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        Resource entity = entityManager.find(Resource.class, id);
        if (entity == null) return null;
        return new ResourceAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByOwner(String ownerId, String resourceServerId) {
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();

        findByOwner(ownerId, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByOwner(String ownerId, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer) {
        findByOwnerFilter(ownerId, resourceServerId, consumer, -1, -1);
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByOwner(String ownerId, String resourceServerId, int first, int max) {
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();

        findByOwnerFilter(ownerId, resourceServerId, list::add, first, max);

        return list;
    }

    private void findByOwnerFilter(String ownerId, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer, int firstResult, int maxResult) {
        boolean pagination = firstResult > -1 && maxResult > -1;
        String queryName = pagination ? "findResourceIdByOwnerOrdered" : "findResourceIdByOwner";

        if (resourceServerId == null) {
            queryName = pagination ? "findAnyResourceIdByOwnerOrdered" : "findAnyResourceIdByOwner";
        }

        TypedQuery<Resource> query = entityManager.createNamedQuery(queryName, Resource.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("owner", ownerId);

        if (resourceServerId != null) {
            query.setParameter("serverId", resourceServerId);
        }

        if (pagination) {
            query.setFirstResult(firstResult);
            query.setMaxResults(maxResult);
        }

        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();
        List<Resource> result = query.getResultList();

        for (Resource entity : result) {
            org.keycloak.authorization.model.Resource cached = resourceStore.findById(entity.getId(), resourceServerId);

            if (cached != null) {
                consumer.accept(cached);
            }
        }
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByUri(String uri, String resourceServerId) {
        TypedQuery<String> query = entityManager.createNamedQuery("findResourceIdByUri", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("uri", uri);
        query.setParameter("serverId", resourceServerId);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            org.keycloak.authorization.model.Resource resource = resourceStore.findById(id, resourceServerId);

            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByResourceServer(String resourceServerId) {
        TypedQuery<String> query = entityManager.createNamedQuery("findResourceIdByServerId", String.class);

        query.setParameter("serverId", resourceServerId);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            org.keycloak.authorization.model.Resource resource = resourceStore.findById(id, resourceServerId);

            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByResourceServer(Map<String, String[]> attributes, String resourceServerId, int firstResult, int maxResult) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Resource> querybuilder = builder.createQuery(Resource.class);
        Root<Resource> root = querybuilder.from(Resource.class);
        querybuilder.select(root.get("id"));
        List<Predicate> predicates = new ArrayList();

        if (resourceServerId != null) {
            predicates.add(builder.equal(root.get("resourceServer").get("id"), resourceServerId));
        }

        attributes.forEach((name, value) -> {
            if ("id".equals(name)) {
                predicates.add(root.get(name).in(value));
            } else if ("scope".equals(name)) {
                predicates.add(root.join("scopes").get("id").in(value));
            } else if ("ownerManagedAccess".equals(name) && value.length > 0) {
                predicates.add(builder.equal(root.get(name), Boolean.valueOf(value[0])));
            } else if ("uri".equals(name) && value.length > 0 && value[0] != null) {
                predicates.add(builder.lower(root.join("uris")).in(value[0].toLowerCase()));
            } else if ("uri_not_null".equals(name)) {
                // predicates.add(builder.isNotEmpty(root.get("uris"))); looks like there is a bug in hibernate and this line doesn't work: https://hibernate.atlassian.net/browse/HHH-6686
                // Workaround
                Expression<Integer> urisSize = builder.size(root.get("uris"));
                predicates.add(builder.notEqual(urisSize, 0));
            } else if ("owner".equals(name)) {
                predicates.add(root.get(name).in(value));
            } else if (!org.keycloak.authorization.model.Resource.EXACT_NAME.equals(name)) {
                if ("name".equals(name) && attributes.containsKey(org.keycloak.authorization.model.Resource.EXACT_NAME) && Boolean.valueOf(attributes.get(org.keycloak.authorization.model.Resource.EXACT_NAME)[0])
                        && value.length > 0 && value[0] != null) {
                    predicates.add(builder.equal(builder.lower(root.get(name)), value[0].toLowerCase()));
                } else if (value.length > 0 && value[0] != null) {
                    predicates.add(builder.like(builder.lower(root.get(name)), "%" + value[0].toLowerCase() + "%"));
                }
            }
        });

        querybuilder.where(predicates.toArray(new Predicate[predicates.size()])).orderBy(builder.asc(root.get("name")));

        Query query = entityManager.createQuery(querybuilder);

        if (firstResult != -1) {
            query.setFirstResult(firstResult);
        }
        if (maxResult != -1) {
            query.setMaxResults(maxResult);
        }

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            org.keycloak.authorization.model.Resource resource = resourceStore.findById(id, resourceServerId);

            if (resource != null) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByScope(List<String> scopes, String resourceServerId) {
        List<org.keycloak.authorization.model.Resource> result = new ArrayList<>();

        findByScope(scopes, resourceServerId, result::add);

        return result;
    }

    @Override
    public void findByScope(List<String> scopes, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer) {
        TypedQuery<Resource> query = entityManager.createNamedQuery("findResourceIdByScope", Resource.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("scopeIds", scopes);
        query.setParameter("serverId", resourceServerId);

        StoreFactory storeFactory = provider.getStoreFactory();

        query.getResultList().stream()
                .map(id -> new ResourceAdapter(id, storeFactory))
                .forEach(consumer);
    }

    @Override
    public org.keycloak.authorization.model.Resource findByName(String name, String resourceServerId) {
        return findByName(name, resourceServerId, resourceServerId);
    }

    @Override
    public org.keycloak.authorization.model.Resource findByName(String name, String ownerId, String resourceServerId) {
        TypedQuery<Resource> query = entityManager.createNamedQuery("findResourceIdByName", Resource.class);

        query.setParameter("serverId", resourceServerId);
        query.setParameter("name", name);
        query.setParameter("ownerId", ownerId);

        try {
            return new ResourceAdapter(query.getSingleResult(), provider.getStoreFactory());
        } catch (NoResultException ex) {
            return null;
        }
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByType(String type, String resourceServerId) {
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();

        findByType(type, resourceServerId, list::add);

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByType(String type, String owner, String resourceServerId) {
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();

        findByType(type, owner, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByType(String type, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer) {
        findByType(type, resourceServerId, resourceServerId, consumer);
    }

    @Override
    public void findByType(String type, String owner, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer) {
        TypedQuery<Resource> query;

        if (owner != null) {
            query = entityManager.createNamedQuery("findResourceIdByType", Resource.class);
        } else {
            query = entityManager.createNamedQuery("findResourceIdByTypeNoOwner", Resource.class);
        }

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("type", type);

        if (owner != null) {
            query.setParameter("ownerId", owner);
        }

        query.setParameter("serverId", resourceServerId);

        StoreFactory storeFactory = provider.getStoreFactory();

        query.getResultList().stream()
                .map(entity -> new ResourceAdapter(entity, storeFactory))
                .forEach(consumer);
    }

    @Override
    public List<org.keycloak.authorization.model.Resource> findByTypeInstance(String type, String resourceServerId) {
        List<org.keycloak.authorization.model.Resource> list = new LinkedList<>();

        findByTypeInstance(type, resourceServerId, list::add);

        return list;
    }

    @Override
    public void findByTypeInstance(String type, String resourceServerId, Consumer<org.keycloak.authorization.model.Resource> consumer) {
        TypedQuery<Resource> query = entityManager.createNamedQuery("findResourceIdByTypeInstance", Resource.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("type", type);
        query.setParameter("serverId", resourceServerId);

        StoreFactory storeFactory = provider.getStoreFactory();

        query.getResultList().stream()
                .map(entity -> new ResourceAdapter(entity, storeFactory))
                .forEach(consumer);
    }
}
