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
package org.keycloak.authorization.admin;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyResourceService {

    protected final ResourceServerModel resourceServer;
    protected final AuthorizationProvider authorization;
    private final PolicyModel policy;

    public PolicyResourceService(PolicyModel policy,
                                 ResourceServerModel resourceServer,
                                 AuthorizationProvider authorization) {
        this.policy = policy;
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    @NoCache
    public Response update(String payload) {
        AbstractPolicyRepresentation representation = doCreateRepresentation(payload);

        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        representation.setId(policy.getId());

        RepresentationToModel.toModel(representation, authorization, policy);

        return Response.status(Status.CREATED).build();
    }

    @DELETE
    public Response delete() {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        StoreFactory storeFactory = authorization.getStoreFactory();
        PolicyStore policyStore = storeFactory.getPolicyStore();
        PolicyProviderFactory resource = getProviderFactory(policy.getType());

        if (resource != null) {
            resource.onRemove(policy, authorization);
        }

        policyStore.delete(policy.getId());

        return Response.noContent().build();
    }

    @GET
    @Produces("application/json")
    @NoCache
    public Response findById(@QueryParam("fields") String fields) {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(toRepresentation(policy, fields, authorization)).build();
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    protected AbstractPolicyRepresentation toRepresentation(PolicyModel policy, String fields, AuthorizationProvider authorization) {
        return modelToRepresentation.toRepresentation(policy, authorization, true, false, fields != null && fields.equals("*"));
    }

    @Path("/dependentPolicies")
    @GET
    @Produces("application/json")
    @NoCache
    public Response getDependentPolicies() {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        List<PolicyModel> policies = authorization.getStoreFactory().getPolicyStore().findDependentPolicies(policy.getId(), resourceServer.getId());

        return Response.ok(policies.stream().map(policy -> {
            PolicyRepresentation representation1 = new PolicyRepresentation();

            representation1.setId(policy.getId());
            representation1.setName(policy.getName());
            representation1.setType(policy.getType());

            return representation1;
        }).collect(Collectors.toList())).build();
    }

    @Path("/scopes")
    @GET
    @Produces("application/json")
    @NoCache
    public Response getScopes() {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(policy.getScopes().stream().map(scope -> {
            ScopeRepresentation representation = new ScopeRepresentation();

            representation.setId(scope.getId());
            representation.setName(scope.getName());

            return representation;
        }).collect(Collectors.toList())).build();
    }

    @Path("/resources")
    @GET
    @Produces("application/json")
    @NoCache
    public Response getResources() {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(policy.getResources().stream().map(resource -> {
            ResourceRepresentation representation = new ResourceRepresentation();

            representation.setId(resource.getId());
            representation.setName(resource.getName());

            return representation;
        }).collect(Collectors.toList())).build();
    }

    @Path("/associatedPolicies")
    @GET
    @Produces("application/json")
    @NoCache
    public Response getAssociatedPolicies() {
        if (policy == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(policy.getAssociatedPolicies().stream().map(policy -> {
            PolicyRepresentation representation1 = new PolicyRepresentation();

            representation1.setId(policy.getId());
            representation1.setName(policy.getName());
            representation1.setType(policy.getType());
            representation1.setDescription(policy.getDescription());

            return representation1;
        }).collect(Collectors.toList())).build();
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

    private PolicyProviderFactory getProviderFactory(String policyType) {
        return authorization.getProviderFactory(policyType);
    }

    protected PolicyModel getPolicy() {
        return policy;
    }
}
