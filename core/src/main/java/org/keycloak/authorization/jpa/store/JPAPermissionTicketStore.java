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
import com.hsbc.unified.iam.entity.authorization.PermissionTicket;
import com.hsbc.unified.iam.repository.authorization.PermissionTicketRepository;
import com.hsbc.unified.iam.repository.authorization.PolicyRepository;
import com.hsbc.unified.iam.facade.model.authorization.PermissionTicketModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.criteria.Predicate;
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

    @Autowired
    private PermissionTicketRepository permissionTicketRepository;
    @Autowired
    private PolicyRepository policyRepository;

    public JPAPermissionTicketStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public PermissionTicketModel create(String resourceId, String scopeId, String requester, ResourceServerModel resourceServer) {
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

        permissionTicketRepository.saveAndFlush(entity);
        return new PermissionTicketAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        permissionTicketRepository.deleteById(id);
    }

    @Override
    public PermissionTicketModel findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        Optional<PermissionTicket> optional = permissionTicketRepository.findById(id);
        return optional.map(permissionTicket -> new PermissionTicketAdapter(permissionTicket, provider.getStoreFactory())).orElse(null);
    }

    @Override
    public List<PermissionTicketModel> findByResourceServer(final String resourceServerId) {
        List<String> result = policyRepository.findPolicyIdByServerId(resourceServerId);
        List<PermissionTicketModel> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            PermissionTicketModel ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<PermissionTicketModel> findByResource(final String resourceId, String resourceServerId) {
        List<String> result = permissionTicketRepository.findPermissionIdByResource(resourceId, resourceServerId);
        List<PermissionTicketModel> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            PermissionTicketModel ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<PermissionTicketModel> findByScope(String scopeId, String resourceServerId) {
        if (scopeId == null) {
            return Collections.emptyList();
        }

        List<String> result = permissionTicketRepository.findPermissionIdByScope(scopeId, resourceServerId);
        List<PermissionTicketModel> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            PermissionTicketModel ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    private Specification<PermissionTicket> findSpecification(Map<String, String> attributes, String resourceServerId) {
        return (Specification<PermissionTicket>) (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (resourceServerId != null) {
                predicates.add(cb.equal(root.get("resourceServer").get("id"), resourceServerId));
            }

            attributes.forEach((name, value) -> {
                if (PermissionTicketModel.ID.equals(name)) {
                    predicates.add(root.get(name).in(value));
                } else if (PermissionTicketModel.SCOPE.equals(name)) {
                    predicates.add(root.join("scope").get("id").in(value));
                } else if (PermissionTicketModel.SCOPE_IS_NULL.equals(name)) {
                    if (Boolean.parseBoolean(value)) {
                        predicates.add(cb.isNull(root.get("scope")));
                    } else {
                        predicates.add(cb.isNotNull(root.get("scope")));
                    }
                } else if (PermissionTicketModel.RESOURCE.equals(name)) {
                    predicates.add(root.join("resource").get("id").in(value));
                } else if (PermissionTicketModel.RESOURCE_NAME.equals(name)) {
                    predicates.add(root.join("resource").get("name").in(value));
                } else if (PermissionTicketModel.OWNER.equals(name)) {
                    predicates.add(cb.equal(root.get("owner"), value));
                } else if (PermissionTicketModel.REQUESTER.equals(name)) {
                    predicates.add(cb.equal(root.get("requester"), value));
                } else if (PermissionTicketModel.GRANTED.equals(name)) {
                    if (Boolean.parseBoolean(value)) {
                        predicates.add(cb.isNotNull(root.get("grantedTimestamp")));
                    } else {
                        predicates.add(cb.isNull(root.get("grantedTimestamp")));
                    }
                } else if (PermissionTicketModel.REQUESTER_IS_NULL.equals(name)) {
                    predicates.add(cb.isNull(root.get("requester")));
                } else if (PermissionTicketModel.POLICY_IS_NOT_NULL.equals(name)) {
                    predicates.add(cb.isNotNull(root.get("policy")));
                } else if (PermissionTicketModel.POLICY.equals(name)) {
                    predicates.add(root.join("policy").get("id").in(value));
                } else {
                    throw new RuntimeException("Unsupported filter [" + name + "]");
                }
            });

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    public List<PermissionTicketModel> find(Map<String, String> attributes, String resourceServerId, int firstResult, int maxResult) {
        List<PermissionTicket> tickets = permissionTicketRepository.findAll(findSpecification(attributes, resourceServerId));

        List<PermissionTicketModel> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (PermissionTicket tick : tickets) {
            PermissionTicketModel ticket = ticketStore.findById(tick.getId(), resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }

    @Override
    public List<PermissionTicketModel> findGranted(String userId, String resourceServerId) {
        HashMap<String, String> filters = new HashMap<>();

        filters.put(PermissionTicketModel.GRANTED, Boolean.TRUE.toString());
        filters.put(PermissionTicketModel.REQUESTER, userId);

        return find(filters, resourceServerId, -1, -1);
    }

    @Override
    public List<PermissionTicketModel> findGranted(String resourceName, String userId, String resourceServerId) {
        HashMap<String, String> filters = new HashMap<>();

        filters.put(PermissionTicketModel.RESOURCE_NAME, resourceName);
        filters.put(PermissionTicketModel.GRANTED, Boolean.TRUE.toString());
        filters.put(PermissionTicketModel.REQUESTER, userId);

        return find(filters, resourceServerId, -1, -1);
    }

    @Override
    public List<ResourceModel> findGrantedResources(String requester, String name, int first, int max) {
        List<String> result;
        if (name != null) {
            result = permissionTicketRepository.findGrantedResourcesByName(requester, "%" + name.toLowerCase() + "%");
        } else {
            result = permissionTicketRepository.findGrantedResources(requester);
        }
        List<ResourceModel> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();
        for (String id : result) {
            ResourceModel resource = resourceStore.findById(id, null);

            if (Objects.nonNull(resource)) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<ResourceModel> findGrantedOwnerResources(String owner, int first, int max) {
        List<String> result = permissionTicketRepository.findGrantedOwnerResources(owner);
        List<ResourceModel> list = new LinkedList<>();
        ResourceStore resourceStore = provider.getStoreFactory().getResourceStore();

        for (String id : result) {
            ResourceModel resource = resourceStore.findById(id, null);

            if (Objects.nonNull(resource)) {
                list.add(resource);
            }
        }

        return list;
    }

    @Override
    public List<PermissionTicketModel> findByOwner(String owner, String resourceServerId) {
        List<String> result = policyRepository.findPolicyIdByType(resourceServerId, owner);
        List<PermissionTicketModel> list = new LinkedList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (String id : result) {
            PermissionTicketModel ticket = ticketStore.findById(id, resourceServerId);
            if (Objects.nonNull(ticket)) {
                list.add(ticket);
            }
        }

        return list;
    }
}
