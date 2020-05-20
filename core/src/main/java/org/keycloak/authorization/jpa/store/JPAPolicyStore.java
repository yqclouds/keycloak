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
import com.hsbc.unified.iam.entity.authorization.Policy;
import com.hsbc.unified.iam.repository.authorization.PolicyRepository;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.NoResultException;
import javax.persistence.criteria.Predicate;
import java.util.*;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAPolicyStore implements PolicyStore {

    private final AuthorizationProvider provider;

    @Autowired
    private ResourceServerAdapter resourceServerAdapter;

    @Autowired
    private PolicyRepository policyRepository;

    public JPAPolicyStore(AuthorizationProvider provider) {
        this.provider = provider;
    }

    @Override
    public PolicyModel create(AbstractPolicyRepresentation representation, ResourceServerModel resourceServer) {
        Policy entity = new Policy();

        if (representation.getId() == null) {
            entity.setId(KeycloakModelUtils.generateId());
        } else {
            entity.setId(representation.getId());
        }

        entity.setType(representation.getType());
        entity.setName(representation.getName());
        entity.setResourceServer(resourceServerAdapter.toEntity(resourceServer));

        policyRepository.save(entity);

        return new PolicyAdapter(entity, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        policyRepository.deleteById(id);
    }

    @Override
    public PolicyModel findById(String id, String resourceServerId) {
        if (id == null) {
            return null;
        }

        Optional<Policy> optional = policyRepository.findById(id);

        return optional.map(policy -> new PolicyAdapter(policy, provider.getStoreFactory())).orElse(null);
    }

    @Override
    public PolicyModel findByName(String name, String resourceServerId) {
        try {
            return new PolicyAdapter(policyRepository.findPolicyIdByName(resourceServerId, name), provider.getStoreFactory());
        } catch (NoResultException ex) {
            return null;
        }
    }

    @Override
    public List<PolicyModel> findByResourceServer(final String resourceServerId) {
        List<String> result = policyRepository.findPolicyIdByServerId(resourceServerId);
        List<PolicyModel> list = new LinkedList<>();
        for (String id : result) {
            PolicyModel policy = provider.getStoreFactory().getPolicyStore().findById(id, resourceServerId);
            if (Objects.nonNull(policy)) {
                list.add(policy);
            }
        }
        return list;
    }

    private Specification<Policy> findByResourceServerSpecification(Map<String, String[]> attributes, String resourceServerId) {
        return (Specification<Policy>) (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            criteriaQuery.select(root.get("id"));

            if (resourceServerId != null) {
                predicates.add(cb.equal(root.get("resourceServer").get("id"), resourceServerId));
            }

            attributes.forEach((name, value) -> {
                if ("permission".equals(name)) {
                    if (Boolean.parseBoolean(value[0])) {
                        predicates.add(root.get("type").in("resource", "scope", "uma"));
                    } else {
                        predicates.add(cb.not(root.get("type").in("resource", "scope", "uma")));
                    }
                } else if ("id".equals(name)) {
                    predicates.add(root.get(name).in((Object) value));
                } else if ("owner".equals(name)) {
                    predicates.add(root.get(name).in((Object) value));
                } else if ("owner_is_not_null".equals(name)) {
                    predicates.add(cb.isNotNull(root.get("owner")));
                } else if ("resource".equals(name)) {
                    predicates.add(root.join("resources").get("id").in((Object) value));
                } else if ("scope".equals(name)) {
                    predicates.add(root.join("scopes").get("id").in((Object) value));
                } else if (name.startsWith("config:")) {
                    predicates.add(root.joinMap("config").key().in(name.substring("config:".length())));
                    predicates.add(cb.like(root.joinMap("config").value().as(String.class), "%" + value[0] + "%"));
                } else {
                    predicates.add(cb.like(cb.lower(root.get(name)), "%" + value[0].toLowerCase() + "%"));
                }
            });

            if (!attributes.containsKey("owner") && !attributes.containsKey("owner_is_not_null")) {
                predicates.add(cb.isNull(root.get("owner")));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    public List<PolicyModel> findByResourceServer(Map<String, String[]> attributes, String resourceServerId, int firstResult, int maxResult) {
        List<Policy> result = policyRepository.findAll(findByResourceServerSpecification(attributes, resourceServerId));
        List<PolicyModel> list = new LinkedList<>();
        for (Policy pol : result) {
            PolicyModel policy = provider.getStoreFactory().getPolicyStore().findById(pol.getId(), resourceServerId);
            if (Objects.nonNull(policy)) {
                list.add(policy);
            }
        }
        return list;
    }

    @Override
    public List<PolicyModel> findByResource(final String resourceId, String resourceServerId) {
        List<PolicyModel> result = new LinkedList<>();

        findByResource(resourceId, resourceServerId, result::add);

        return result;
    }

    @Override
    public void findByResource(String resourceId, String resourceServerId, Consumer<PolicyModel> consumer) {
        StoreFactory storeFactory = provider.getStoreFactory();

        policyRepository.findPolicyIdByResource(resourceId, resourceServerId).stream()
                .map(entity -> new PolicyAdapter(entity, storeFactory))
                .forEach(consumer);
    }

    @Override
    public List<PolicyModel> findByResourceType(final String resourceType, String resourceServerId) {
        List<PolicyModel> result = new LinkedList<>();

        findByResourceType(resourceType, resourceServerId, result::add);

        return result;
    }

    @Override
    public void findByResourceType(String resourceType, String resourceServerId, Consumer<PolicyModel> consumer) {
        policyRepository.findPolicyIdByResourceType(resourceType, resourceServerId).stream()
                .map(id -> new PolicyAdapter(id, provider.getStoreFactory()))
                .forEach(consumer);
    }

    @Override
    public List<PolicyModel> findByScopeIds(List<String> scopeIds, String resourceServerId) {
        if (scopeIds == null || scopeIds.isEmpty()) {
            return Collections.emptyList();
        }

        List<PolicyModel> list = new LinkedList<>();
        StoreFactory storeFactory = provider.getStoreFactory();

        for (Policy entity : policyRepository.findPolicyIdByScope(scopeIds, resourceServerId)) {
            list.add(new PolicyAdapter(entity, storeFactory));
        }

        return list;
    }

    @Override
    public List<PolicyModel> findByScopeIds(List<String> scopeIds, String resourceId, String resourceServerId) {
        List<PolicyModel> result = new LinkedList<>();

        findByScopeIds(scopeIds, resourceId, resourceServerId, result::add);

        return result;
    }

    @Override
    public void findByScopeIds(List<String> scopeIds, String resourceId, String resourceServerId, Consumer<PolicyModel> consumer) {
        // Use separate subquery to handle DB2 and MSSSQL
        List<Policy> results;
        if (resourceId == null) {
            results = policyRepository.findPolicyIdByNullResourceScope(scopeIds, resourceServerId);
        } else {
            results = policyRepository.findPolicyIdByResourceScope(scopeIds, resourceId, resourceServerId);
        }

        StoreFactory storeFactory = provider.getStoreFactory();

        results.stream().map(id -> new PolicyAdapter(id, storeFactory))
                .forEach(consumer);
    }

    @Override
    public List<PolicyModel> findByType(String type, String resourceServerId) {
        List<String> result = policyRepository.findPolicyIdByType(resourceServerId, type);
        List<PolicyModel> list = new LinkedList<>();
        for (String id : result) {
            PolicyModel policy = provider.getStoreFactory().getPolicyStore().findById(id, resourceServerId);
            if (Objects.nonNull(policy)) {
                list.add(policy);
            }
        }
        return list;
    }

    @Override
    public List<PolicyModel> findDependentPolicies(String policyId, String resourceServerId) {
        List<String> result = policyRepository.findPolicyIdByDependentPolices(resourceServerId, policyId);
        List<PolicyModel> list = new LinkedList<>();
        for (String id : result) {
            PolicyModel policy = provider.getStoreFactory().getPolicyStore().findById(id, resourceServerId);
            if (Objects.nonNull(policy)) {
                list.add(policy);
            }
        }
        return list;
    }
}
