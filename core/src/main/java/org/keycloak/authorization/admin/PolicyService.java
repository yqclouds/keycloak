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
package org.keycloak.authorization.admin;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderAdminService;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyProviderRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyService {

    protected final ResourceServerModel resourceServer;
    protected final AuthorizationProvider authorization;
    protected final AdminPermissionEvaluator auth;

    public PolicyService(ResourceServerModel resourceServer, AuthorizationProvider authorization, AdminPermissionEvaluator auth) {
        this.resourceServer = resourceServer;
        this.authorization = authorization;
        this.auth = auth;
    }

    @Path("{type}")
    public Object getResource(@PathParam("type") String type) {
        PolicyProviderFactory providerFactory = getPolicyProviderFactory(type);

        if (providerFactory != null) {
            return doCreatePolicyTypeResource(type);
        }

        PolicyModel policy = authorization.getStoreFactory().getPolicyStore().findById(type, resourceServer.getId());

        return doCreatePolicyResource(policy);
    }

    protected PolicyTypeService doCreatePolicyTypeResource(String type) {
        return new PolicyTypeService(type, resourceServer, authorization, auth);
    }

    protected Object doCreatePolicyResource(PolicyModel policy) {
        return new PolicyResourceService(policy, resourceServer, authorization, auth);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response create(String payload) {
        if (auth != null) {
            this.auth.realm().requireManageAuthorization();
        }

        AbstractPolicyRepresentation representation = doCreateRepresentation(payload);
        PolicyModel policy = create(representation);

        representation.setId(policy.getId());

        return Response.status(Status.CREATED).entity(representation).build();
    }

    protected AbstractPolicyRepresentation doCreateRepresentation(String payload) {
        PolicyRepresentation representation;

        try {
            representation = JsonSerialization.readValue(payload, PolicyRepresentation.class);
        } catch (IOException cause) {
            throw new RuntimeException("Failed to deserialize representation", cause);
        }

        return representation;
    }

    public PolicyModel create(AbstractPolicyRepresentation representation) {
        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();
        PolicyModel existing = policyStore.findByName(representation.getName(), resourceServer.getId());

        if (existing != null) {
            throw new ErrorResponseException("PolicyModel with name [" + representation.getName() + "] already exists", "Conflicting policy", Status.CONFLICT);
        }

        return policyStore.create(representation, resourceServer);
    }

    @Path("/search")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response findByName(@QueryParam("name") String name, @QueryParam("fields") String fields) {
        if (auth != null) {
            this.auth.realm().requireViewAuthorization();
        }

        StoreFactory storeFactory = authorization.getStoreFactory();

        if (name == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        PolicyModel model = storeFactory.getPolicyStore().findByName(name, this.resourceServer.getId());

        if (model == null) {
            return Response.status(Status.OK).build();
        }

        return Response.ok(toRepresentation(model, fields, authorization)).build();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response findAll(@QueryParam("policyId") String id,
                            @QueryParam("name") String name,
                            @QueryParam("type") String type,
                            @QueryParam("resource") String resource,
                            @QueryParam("scope") String scope,
                            @QueryParam("permission") Boolean permission,
                            @QueryParam("owner") String owner,
                            @QueryParam("fields") String fields,
                            @QueryParam("first") Integer firstResult,
                            @QueryParam("max") Integer maxResult) {
        if (auth != null) {
            this.auth.realm().requireViewAuthorization();
        }

        Map<String, String[]> search = new HashMap<>();

        if (id != null && !"".equals(id.trim())) {
            search.put("id", new String[]{id});
        }

        if (name != null && !"".equals(name.trim())) {
            search.put("name", new String[]{name});
        }

        if (type != null && !"".equals(type.trim())) {
            search.put("type", new String[]{type});
        }

        if (owner != null && !"".equals(owner.trim())) {
            search.put("owner", new String[]{owner});
        }

        StoreFactory storeFactory = authorization.getStoreFactory();

        if (resource != null && !"".equals(resource.trim())) {
            ResourceStore resourceStore = storeFactory.getResourceStore();
            ResourceModel resourceModel = resourceStore.findById(resource, resourceServer.getId());

            if (resourceModel == null) {
                Map<String, String[]> resourceFilters = new HashMap<>();

                resourceFilters.put("name", new String[]{resource});

                if (owner != null) {
                    resourceFilters.put("owner", new String[]{owner});
                }

                Set<String> resources = resourceStore.findByResourceServer(resourceFilters, resourceServer.getId(), -1, 1).stream().map(ResourceModel::getId).collect(Collectors.toSet());

                if (resources.isEmpty()) {
                    return Response.ok().build();
                }

                search.put("resource", resources.toArray(new String[0]));
            } else {
                search.put("resource", new String[]{resourceModel.getId()});
            }
        }

        if (scope != null && !"".equals(scope.trim())) {
            ScopeStore scopeStore = storeFactory.getScopeStore();
            ScopeModel scopeModel = scopeStore.findById(scope, resourceServer.getId());

            if (scopeModel == null) {
                Map<String, String[]> scopeFilters = new HashMap<>();

                scopeFilters.put("name", new String[]{scope});

                Set<String> scopes = scopeStore.findByResourceServer(scopeFilters, resourceServer.getId(), -1, 1).stream().map(ScopeModel::getId).collect(Collectors.toSet());

                if (scopes.isEmpty()) {
                    return Response.ok().build();
                }

                search.put("scope", scopes.toArray(new String[scopes.size()]));
            } else {
                search.put("scope", new String[]{scopeModel.getId()});
            }
        }

        if (permission != null) {
            search.put("permission", new String[]{permission.toString()});
        }

        return Response.ok(
                doSearch(firstResult, maxResult, fields, search))
                .build();
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    protected AbstractPolicyRepresentation toRepresentation(PolicyModel model, String fields, AuthorizationProvider authorization) {
        return modelToRepresentation.toRepresentation(model, authorization, true, false, fields != null && fields.equals("*"));
    }

    protected List<Object> doSearch(Integer firstResult, Integer maxResult, String fields, Map<String, String[]> filters) {
        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();
        return policyStore.findByResourceServer(filters, resourceServer.getId(), firstResult != null ? firstResult : -1, maxResult != null ? maxResult : Constants.DEFAULT_MAX_RESULTS).stream()
                .map(policy -> toRepresentation(policy, fields, authorization))
                .collect(Collectors.toList());
    }

    @Path("providers")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response findPolicyProviders() {
        if (auth != null) {
            this.auth.realm().requireViewAuthorization();
        }

        return Response.ok(
                authorization.getProviderFactories().stream()
                        .filter(factory -> !factory.isInternal())
                        .map(factory -> {
                            PolicyProviderRepresentation representation = new PolicyProviderRepresentation();

                            representation.setName(factory.getName());
                            representation.setGroup(factory.getGroup());
                            representation.setType(factory.getId());

                            return representation;
                        })
                        .collect(Collectors.toList()))
                .build();
    }

    @Path("evaluate")
    public PolicyEvaluationService getPolicyEvaluateResource() {
        if (auth != null) {
            this.auth.realm().requireViewAuthorization();
        }

        PolicyEvaluationService resource = new PolicyEvaluationService(this.resourceServer, this.authorization, this.auth);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    protected PolicyProviderAdminService getPolicyProviderAdminResource(String policyType) {
        return getPolicyProviderFactory(policyType).getAdminResource(resourceServer, authorization);
    }

    protected PolicyProviderFactory getPolicyProviderFactory(String policyType) {
        return authorization.getProviderFactory(policyType);
    }
}
