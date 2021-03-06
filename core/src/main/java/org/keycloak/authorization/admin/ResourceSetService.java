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
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.util.PathMatcher;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceOwnerRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceSetService {

    private final AuthorizationProvider authorization;
    private final ResourceServerModel resourceServer;

    @Autowired
    private RepresentationToModel representationToModel;

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    public ResourceSetService(ResourceServerModel resourceServer,
                              AuthorizationProvider authorization) {
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    @POST
    @NoCache
    @Consumes("application/json")
    @Produces("application/json")
    public Response createPost(ResourceRepresentation resource) {
        if (resource == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        ResourceRepresentation newResource = create(resource);

        return Response.status(Status.CREATED).entity(newResource).build();
    }

    public ResourceRepresentation create(ResourceRepresentation resource) {
        StoreFactory storeFactory = this.authorization.getStoreFactory();
        ResourceOwnerRepresentation owner = resource.getOwner();

        if (owner == null) {
            owner = new ResourceOwnerRepresentation();
            owner.setId(resourceServer.getId());
            resource.setOwner(owner);
        }

        String ownerId = owner.getId();

        if (ownerId == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "You must specify the resource owner.", Status.BAD_REQUEST);
        }

        ResourceModel existingResource = storeFactory.getResourceStore().findByName(resource.getName(), ownerId, this.resourceServer.getId());

        if (existingResource != null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "ResourceModel with name [" + resource.getName() + "] already exists.", Status.CONFLICT);
        }

        return modelToRepresentation.toRepresentation(representationToModel.toModel(resource, this.resourceServer, authorization), resourceServer, authorization);
    }

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(@PathParam("id") String id, ResourceRepresentation resource) {
        resource.setId(id);
        StoreFactory storeFactory = this.authorization.getStoreFactory();
        ResourceStore resourceStore = storeFactory.getResourceStore();
        ResourceModel model = resourceStore.findById(resource.getId(), resourceServer.getId());

        if (model == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        representationToModel.toModel(resource, resourceServer, authorization);

        return Response.noContent().build();
    }

    @Path("{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceModel resource = storeFactory.getResourceStore().findById(id, resourceServer.getId());

        if (resource == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        storeFactory.getResourceStore().delete(id);

        return Response.noContent().build();
    }

    @Path("{id}")
    @GET
    @NoCache
    @Produces("application/json")
    public Response findById(@PathParam("id") String id) {
        return findById(id, resource -> modelToRepresentation.toRepresentation(resource, resourceServer, authorization, true));
    }

    public Response findById(String id, Function<ResourceModel, ? extends ResourceRepresentation> toRepresentation) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceModel model = storeFactory.getResourceStore().findById(id, resourceServer.getId());

        if (model == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(toRepresentation.apply(model)).build();
    }

    @Path("{id}/scopes")
    @GET
    @NoCache
    @Produces("application/json")
    public Response getScopes(@PathParam("id") String id) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceModel model = storeFactory.getResourceStore().findById(id, resourceServer.getId());

        if (model == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        List<ScopeRepresentation> scopes = model.getScopes().stream().map(scope -> {
            ScopeRepresentation representation = new ScopeRepresentation();

            representation.setId(scope.getId());
            representation.setName(scope.getName());

            return representation;
        }).collect(Collectors.toList());

        if (model.getType() != null && !model.getOwner().equals(resourceServer.getId())) {
            ResourceStore resourceStore = authorization.getStoreFactory().getResourceStore();
            for (ResourceModel typed : resourceStore.findByType(model.getType(), resourceServer.getId())) {
                if (typed.getOwner().equals(resourceServer.getId()) && !typed.getId().equals(model.getId())) {
                    scopes.addAll(typed.getScopes().stream().map(model1 -> {
                        ScopeRepresentation scope = new ScopeRepresentation();
                        scope.setId(model1.getId());
                        scope.setName(model1.getName());
                        String iconUri = model1.getIconUri();
                        if (iconUri != null) {
                            scope.setIconUri(iconUri);
                        }
                        return scope;
                    }).filter(scopeRepresentation -> !scopes.contains(scopeRepresentation)).collect(Collectors.toList()));
                }
            }
        }

        return Response.ok(scopes).build();
    }

    @Path("{id}/permissions")
    @GET
    @NoCache
    @Produces("application/json")
    public Response getPermissions(@PathParam("id") String id) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceStore resourceStore = storeFactory.getResourceStore();
        ResourceModel model = resourceStore.findById(id, resourceServer.getId());

        if (model == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();

        Set<PolicyModel> policies = new HashSet<>(policyStore.findByResource(model.getId(), resourceServer.getId()));

        if (model.getType() != null) {
            policies.addAll(policyStore.findByResourceType(model.getType(), resourceServer.getId()));

            HashMap<String, String[]> resourceFilter = new HashMap<>();

            resourceFilter.put("owner", new String[]{resourceServer.getId()});
            resourceFilter.put("type", new String[]{model.getType()});

            for (ResourceModel resourceType : resourceStore.findByResourceServer(resourceFilter, resourceServer.getId(), -1, -1)) {
                policies.addAll(policyStore.findByResource(resourceType.getId(), resourceServer.getId()));
            }
        }

        policies.addAll(policyStore.findByScopeIds(model.getScopes().stream().map(ScopeModel::getId).collect(Collectors.toList()), id, resourceServer.getId()));
        policies.addAll(policyStore.findByScopeIds(model.getScopes().stream().map(ScopeModel::getId).collect(Collectors.toList()), null, resourceServer.getId()));

        List<PolicyRepresentation> representation = new ArrayList<>();

        for (PolicyModel policyModel : policies) {
            if (!"uma".equalsIgnoreCase(policyModel.getType())) {
                PolicyRepresentation policy = new PolicyRepresentation();

                policy.setId(policyModel.getId());
                policy.setName(policyModel.getName());
                policy.setType(policyModel.getType());

                if (!representation.contains(policy)) {
                    representation.add(policy);
                }
            }
        }

        return Response.ok(representation).build();
    }

    @Path("{id}/attributes")
    @GET
    @NoCache
    @Produces("application/json")
    public Response getAttributes(@PathParam("id") String id) {
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceModel model = storeFactory.getResourceStore().findById(id, resourceServer.getId());

        if (model == null) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok(model.getAttributes()).build();
    }

    @Path("/search")
    @GET
    @NoCache
    @Produces("application/json")
    public Response find(@QueryParam("name") String name) {
        StoreFactory storeFactory = authorization.getStoreFactory();

        if (name == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        ResourceModel model = storeFactory.getResourceStore().findByName(name, this.resourceServer.getId());

        if (model == null) {
            return Response.status(Status.OK).build();
        }

        return Response.ok(modelToRepresentation.toRepresentation(model, this.resourceServer, authorization)).build();
    }

    @GET
    @NoCache
    @Produces("application/json")
    public Response find(@QueryParam("_id") String id,
                         @QueryParam("name") String name,
                         @QueryParam("uri") String uri,
                         @QueryParam("owner") String owner,
                         @QueryParam("type") String type,
                         @QueryParam("scope") String scope,
                         @QueryParam("matchingUri") Boolean matchingUri,
                         @QueryParam("exactName") Boolean exactName,
                         @QueryParam("deep") Boolean deep,
                         @QueryParam("first") Integer firstResult,
                         @QueryParam("max") Integer maxResult) {
        return find(id, name, uri, owner, type, scope, matchingUri, exactName, deep, firstResult, maxResult, (BiFunction<ResourceModel, Boolean, ResourceRepresentation>) (resource, deep1) -> modelToRepresentation.toRepresentation(resource, resourceServer, authorization, deep1));
    }

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private UserProvider userProvider;

    public Response find(@QueryParam("_id") String id,
                         @QueryParam("name") String name,
                         @QueryParam("uri") String uri,
                         @QueryParam("owner") String owner,
                         @QueryParam("type") String type,
                         @QueryParam("scope") String scope,
                         @QueryParam("matchingUri") Boolean matchingUri,
                         @QueryParam("exactName") Boolean exactName,
                         @QueryParam("deep") Boolean deep,
                         @QueryParam("first") Integer firstResult,
                         @QueryParam("max") Integer maxResult,
                         BiFunction<ResourceModel, Boolean, ?> toRepresentation) {
        StoreFactory storeFactory = authorization.getStoreFactory();

        if (deep == null) {
            deep = true;
        }

        Map<String, String[]> search = new HashMap<>();

        if (id != null && !"".equals(id.trim())) {
            search.put("id", new String[]{id});
        }

        if (name != null && !"".equals(name.trim())) {
            search.put("name", new String[]{name});

            if (exactName != null && exactName) {
                search.put(ResourceModel.EXACT_NAME, new String[]{Boolean.TRUE.toString()});
            }
        }

        if (uri != null && !"".equals(uri.trim())) {
            search.put("uri", new String[]{uri});
        }

        if (owner != null && !"".equals(owner.trim())) {
            RealmModel realm = keycloakContext.getRealm();
            ClientModel clientModel = realm.getClientByClientId(owner);

            if (clientModel != null) {
                owner = clientModel.getId();
            } else {
                UserModel user = userProvider.getUserByUsername(owner, realm);

                if (user != null) {
                    owner = user.getId();
                }
            }

            search.put("owner", new String[]{owner});
        }

        if (type != null && !"".equals(type.trim())) {
            search.put("type", new String[]{type});
        }

        if (scope != null && !"".equals(scope.trim())) {
            HashMap<String, String[]> scopeFilter = new HashMap<>();

            scopeFilter.put("name", new String[]{scope});

            List<ScopeModel> scopes = authorization.getStoreFactory().getScopeStore().findByResourceServer(scopeFilter, resourceServer.getId(), -1, -1);

            if (scopes.isEmpty()) {
                return Response.ok(Collections.emptyList()).build();
            }

            search.put("scope", scopes.stream().map(ScopeModel::getId).toArray(String[]::new));
        }

        List<ResourceModel> resources = storeFactory.getResourceStore().findByResourceServer(search, this.resourceServer.getId(), firstResult != null ? firstResult : -1, maxResult != null ? maxResult : Constants.DEFAULT_MAX_RESULTS);

        if (matchingUri != null && matchingUri && resources.isEmpty()) {
            HashMap<String, String[]> attributes = new HashMap<>();

            attributes.put("uri_not_null", new String[]{"true"});
            attributes.put("owner", new String[]{resourceServer.getId()});

            List<ResourceModel> serverResources = storeFactory.getResourceStore().findByResourceServer(attributes, this.resourceServer.getId(), firstResult != null ? firstResult : -1, maxResult != null ? maxResult : -1);

            PathMatcher<Map.Entry<String, ResourceModel>> pathMatcher = new PathMatcher<Map.Entry<String, ResourceModel>>() {
                @Override
                protected String getPath(Map.Entry<String, ResourceModel> entry) {
                    return entry.getKey();
                }

                @Override
                protected Collection<Map.Entry<String, ResourceModel>> getPaths() {
                    Map<String, ResourceModel> result = new HashMap<>();
                    serverResources.forEach(resource -> resource.getUris().forEach(uri -> {
                        result.put(uri, resource);
                    }));

                    return result.entrySet();
                }
            };

            Map.Entry<String, ResourceModel> matches = pathMatcher.matches(uri);

            if (matches != null) {
                resources = Collections.singletonList(matches.getValue());
            }
        }

        Boolean finalDeep = deep;

        return Response.ok(
                resources.stream()
                        .map(resource -> toRepresentation.apply(resource, finalDeep))
                        .collect(Collectors.toList()))
                .build();
    }
}
