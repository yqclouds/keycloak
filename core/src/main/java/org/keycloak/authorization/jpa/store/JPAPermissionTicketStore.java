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

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.jpa.entities.PermissionTicket;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.FlushModeType;
import javax.persistence.LockModeType;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAPermissionTicketStore implements PermissionTicketStore {

    private final AuthorizationProvider provider;

    @Autowired
    private ResourceAdapter resourceAdapter;
    @Autowired
    private ScopeAdapter scopeAdapter;
    @Autowired
    private ResourceServerAdapter resourceServerAdapter;

    public JPAPermissionTicketStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public org.keycloak.authorization.model.PermissionTicket create(String resourceId, String scopeId, String requester, ResourceServer resourceServer) {
        PermissionTicket entity = new PermissionTicket();

        entity.setId(KeycloakModelUtils.generateId());
        entity.setResource(resourceAdapter.toEntity(provider.getStoreFactory().getResourceStore().findById(resourceId, resourceServer.getId())));
        entity.setRequester(requester);
        entity.setCreatedTimestamp(System.currentTimeMillis());

        if (scopeId != null) {
            entity.setScope(scopeAdapter.toEntity(provider.getStoreFactory().getScopeStore().findById(scopeId, resourceServer.getId())));
        }

        entity.setOwner(entity.getResource().getOwner());
        entity.setResourceServer(resourceServerAdapter.toEntity(resourceServer));

        this.entityManager.persist(entity);
        this.entityManager.flush();
        org.keycloak.authorization.model.PermissionTicket model = new PermissionTicketAdapter(entity, provider.getStoreFactory());
        return model;
    }

    @Override
    public void delete(String id) {
        PermissionTicket policy = entityManager.find(PermissionTicket.class, id, LockModeType.PESSIMISTIC_WRITE);
        if (policy != null) {
            this.entityManager.remove(policy);
        }
    }


    @Override
    public org.keycloak.authorization.model.PermissionTicket findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        PermissionTicket entity = entityManager.find(PermissionTicket.class, id);
        if (entity == null) return null;

        return new PermissionTicketAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findByResourceServer(final String resourceServerId) {
        TypedQuery<String> query = entityManager.createNamedQuery("findPolicyIdByServerId", String.class);

        query.setParameter("serverId", resourceServerId);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.PermissionTicket> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            org.keycloak.authorization.model.PermissionTicket ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findByResource(final String resourceId, String resourceServerId) {
        TypedQuery<String> query = entityManager.createNamedQuery("findPermissionIdByResource", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("resourceId", resourceId);
        query.setParameter("serverId", resourceServerId);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.PermissionTicket> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            org.keycloak.authorization.model.PermissionTicket ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findByScope(String scopeId, String resourceServerId) {
        if (scopeId == null) {
            return Collections.emptyList();
        }

        // Use separate subquery to handle DB2 and MSSSQL
        TypedQuery<String> query = entityManager.createNamedQuery("findPermissionIdByScope", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("scopeId", scopeId);
        query.setParameter("serverId", resourceServerId);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.PermissionTicket> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            org.keycloak.authorization.model.PermissionTicket ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> find(Map<String, String> attributes, String resourceServerId, int firstResult, int maxResult) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<PermissionTicket> querybuilder = builder.createQuery(PermissionTicket.class);
        Root<PermissionTicket> root = querybuilder.from(PermissionTicket.class);

        querybuilder.select(root.get("id"));

        List<Predicate> predicates = new ArrayList();

        if (resourceServerId != null) {
            predicates.add(builder.equal(root.get("resourceServer").get("id"), resourceServerId));
        }

        attributes.forEach((name, value) -> {
            if (org.keycloak.authorization.model.PermissionTicket.ID.equals(name)) {
                predicates.add(root.get(name).in(value));
            } else if (org.keycloak.authorization.model.PermissionTicket.SCOPE.equals(name)) {
                predicates.add(root.join("scope").get("id").in(value));
            } else if (org.keycloak.authorization.model.PermissionTicket.SCOPE_IS_NULL.equals(name)) {
                if (Boolean.valueOf(value)) {
                    predicates.add(builder.isNull(root.get("scope")));
                } else {
                    predicates.add(builder.isNotNull(root.get("scope")));
                }
            } else if (org.keycloak.authorization.model.PermissionTicket.RESOURCE.equals(name)) {
                predicates.add(root.join("resource").get("id").in(value));
            } else if (org.keycloak.authorization.model.PermissionTicket.RESOURCE_NAME.equals(name)) {
                predicates.add(root.join("resource").get("name").in(value));
            } else if (org.keycloak.authorization.model.PermissionTicket.OWNER.equals(name)) {
                predicates.add(builder.equal(root.get("owner"), value));
            } else if (org.keycloak.authorization.model.PermissionTicket.REQUESTER.equals(name)) {
                predicates.add(builder.equal(root.get("requester"), value));
            } else if (org.keycloak.authorization.model.PermissionTicket.GRANTED.equals(name)) {
                if (Boolean.valueOf(value)) {
                    predicates.add(builder.isNotNull(root.get("grantedTimestamp")));
                } else {
                    predicates.add(builder.isNull(root.get("grantedTimestamp")));
                }
            } else if (org.keycloak.authorization.model.PermissionTicket.REQUESTER_IS_NULL.equals(name)) {
                predicates.add(builder.isNull(root.get("requester")));
            } else if (org.keycloak.authorization.model.PermissionTicket.POLICY_IS_NOT_NULL.equals(name)) {
                predicates.add(builder.isNotNull(root.get("policy")));
            } else if (org.keycloak.authorization.model.PermissionTicket.POLICY.equals(name)) {
                predicates.add(root.join("policy").get("id").in(value));
            } else {
                throw new RuntimeException("Unsupported filter [" + name + "]");
            }
        });

        querybuilder.where(predicates.toArray(new Predicate[predicates.size()])).orderBy(builder.asc(root.get("id")));

        Query query = entityManager.createQuery(querybuilder);

        if (firstResult != -1) {
            query.setFirstResult(firstResult);
        }

        if (maxResult != -1) {
            query.setMaxResults(maxResult);
        }

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.PermissionTicket> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            org.keycloak.authorization.model.PermissionTicket ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findGranted(String userId, String resourceServerId) {
        HashMap<String, String> filters = new HashMap<>();

        filters.put(org.keycloak.authorization.model.PermissionTicket.GRANTED, Boolean.TRUE.toString());
        filters.put(org.keycloak.authorization.model.PermissionTicket.REQUESTER, userId);

        return find(filters, resourceServerId, -1, -1);
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findGranted(String resourceName, String userId, String resourceServerId) {
        HashMap<String, String> filters = new HashMap<>();

        filters.put(org.keycloak.authorization.model.PermissionTicket.RESOURCE_NAME, resourceName);
        filters.put(org.keycloak.authorization.model.PermissionTicket.GRANTED, Boolean.TRUE.toString());
        filters.put(org.keycloak.authorization.model.PermissionTicket.REQUESTER, userId);

        return find(filters, resourceServerId, -1, -1);
    }

    @Override
    public List<Resource> findGrantedResources(String requester, String name, int first, int max) {
        TypedQuery<String> query = name == null ?
                entityManager.createNamedQuery("findGrantedResources", String.class) :
                entityManager.createNamedQuery("findGrantedResourcesByName", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("requester", requester);

        if (name != null) {
            query.setParameter("resourceName", "%" + name.toLowerCase() + "%");
        }

        if (first > -1 && max > -1) {
            query.setFirstResult(first);
            query.setMaxResults(max);
        }

        List<String> result = query.getResultList();
        List<Resource> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            Resource resource = resourceStore.findById(id, null);

            if (Objects.nonNull(resource)) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<Resource> findGrantedOwnerResources(String owner, int first, int max) {
        TypedQuery<String> query = entityManager.createNamedQuery("findGrantedOwnerResources", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("owner", owner);

        if (first > -1 && max > -1) {
            query.setFirstResult(first);
            query.setMaxResults(max);
        }

        List<String> result = query.getResultList();
        List<Resource> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            Resource resource = resourceStore.findById(id, null);

            if (Objects.nonNull(resource)) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<org.keycloak.authorization.model.PermissionTicket> findByOwner(String owner, String resourceServerId) {
        TypedQuery<String> query = entityManager.createNamedQuery("findPolicyIdByType", String.class);

        query.setFlushMode(FlushModeType.COMMIT);
        query.setParameter("serverId", resourceServerId);
        query.setParameter("owner", owner);

        List<String> result = query.getResultList();
        List<org.keycloak.authorization.model.PermissionTicket> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            org.keycloak.authorization.model.PermissionTicket ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }
}
