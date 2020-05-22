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

import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.exportimport.util.ExportUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.*;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpSession;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.Collections;
import java.util.HashMap;

import static org.keycloak.models.utils.ModelToRepresentation.toRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServerService {

    private final AuthorizationProvider authorizationProvider;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;
    private final ClientModel client;
    private ResourceServerModel resourceServer;

    public ResourceServerService(AuthorizationProvider authorization, ResourceServerModel resourceServer, ClientModel client, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.authorizationProvider = authorization;
        this.client = client;
        this.resourceServer = resourceServer;
        this.auth = auth;
        this.adminEvent = adminEvent;
    }

    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private UserProvider userProvider;
    @Autowired
    private KeycloakContext keycloakContext;

    public ResourceServerModel create(boolean newClient) {
        this.auth.realm().requireManageAuthorization();

        UserModel serviceAccount = userProvider.getServiceAccount(client);

        if (serviceAccount == null) {
            throw new RuntimeException("Client does not have a service account.");
        }

        if (this.resourceServer == null) {
            this.resourceServer = representationToModel.createResourceServer(client, true);
            createDefaultPermission(createDefaultResource(), createDefaultPolicy());
            audit(OperationType.CREATE, keycloakContext.getUri(), newClient);
        }

        return resourceServer;
    }

    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(ResourceServerRepresentation server) {
        this.auth.realm().requireManageAuthorization();
        this.resourceServer.setAllowRemoteResourceManagement(server.isAllowRemoteResourceManagement());
        this.resourceServer.setPolicyEnforcementMode(server.getPolicyEnforcementMode());
        this.resourceServer.setDecisionStrategy(server.getDecisionStrategy());
        audit(OperationType.UPDATE, keycloakContext.getUri(), false);
        return Response.noContent().build();
    }

    public void delete() {
        this.auth.realm().requireManageAuthorization();
        authorizationProvider.getStoreFactory().getResourceServerStore().delete(resourceServer.getId());
        audit(OperationType.DELETE, keycloakContext.getUri(), false);
    }

    @GET
    @Produces("application/json")
    public Response findById() {
        this.auth.realm().requireViewAuthorization();
        return Response.ok(toRepresentation(this.resourceServer, this.client)).build();
    }

    @Autowired
    private ExportUtils exportUtils;

    @Path("/settings")
    @GET
    @Produces("application/json")
    public Response exportSettings() {
        this.auth.realm().requireManageAuthorization();
        return Response.ok(exportUtils.exportAuthorizationSettings(client)).build();
    }

    @Path("/import")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response importSettings(ResourceServerRepresentation rep) {
        this.auth.realm().requireManageAuthorization();

        rep.setClientId(client.getId());

        representationToModel.toModel(rep, authorizationProvider);

        audit(OperationType.UPDATE, keycloakContext.getUri(), false);

        return Response.noContent().build();
    }

    @Path("/resource")
    public ResourceSetService getResourceSetResource() {
        ResourceSetService resource = new ResourceSetService(this.resourceServer, this.authorizationProvider, this.auth, adminEvent);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/scope")
    public ScopeService getScopeResource() {
        ScopeService resource = new ScopeService(this.resourceServer, this.authorizationProvider, this.auth, adminEvent);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/policy")
    public PolicyService getPolicyResource() {
        PolicyService resource = new PolicyService(this.resourceServer, this.authorizationProvider, this.auth, adminEvent);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/permission")
    public Object getPermissionTypeResource() {
        this.auth.realm().requireViewAuthorization();
        PermissionService resource = new PermissionService(this.resourceServer, this.authorizationProvider, this.auth, adminEvent);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    private void createDefaultPermission(ResourceRepresentation resource, PolicyRepresentation policy) {
        ResourcePermissionRepresentation defaultPermission = new ResourcePermissionRepresentation();

        defaultPermission.setName("Default Permission");
        defaultPermission.setDescription("A permission that applies to the default resource type");
        defaultPermission.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        defaultPermission.setLogic(Logic.POSITIVE);

        defaultPermission.setResourceType(resource.getType());
        defaultPermission.addPolicy(policy.getName());

        getPolicyResource().create(defaultPermission);
    }

    private HttpSession httpSession;

    private PolicyRepresentation createDefaultPolicy() {
        PolicyRepresentation defaultPolicy = new PolicyRepresentation();

        defaultPolicy.setName("Default PolicyModel");
        defaultPolicy.setDescription("A policy that grants access only for users within this realm");
        defaultPolicy.setType("js");
        defaultPolicy.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        defaultPolicy.setLogic(Logic.POSITIVE);

        HashMap<String, String> defaultPolicyConfig = new HashMap<>();

        defaultPolicyConfig.put("code", "// by default, grants any permission associated with this policy\n$evaluation.grant();\n");

        defaultPolicy.setConfig(defaultPolicyConfig);

        httpSession.setAttribute("ALLOW_CREATE_POLICY", true);

        getPolicyResource().create(defaultPolicy);

        return defaultPolicy;
    }

    private ResourceRepresentation createDefaultResource() {
        ResourceRepresentation defaultResource = new ResourceRepresentation();

        defaultResource.setName("Default ResourceModel");
        defaultResource.setUris(Collections.singleton("/*"));
        defaultResource.setType("urn:" + this.client.getClientId() + ":resources:default");

        getResourceSetResource().create(defaultResource);
        return defaultResource;
    }

    private void audit(OperationType operation, UriInfo uriInfo, boolean newClient) {
        if (newClient) {
            adminEvent.resource(ResourceType.AUTHORIZATION_RESOURCE_SERVER).operation(operation).resourcePath(uriInfo, client.getId())
                    .representation(ModelToRepresentation.toRepresentation(resourceServer, client)).success();
        } else {
            adminEvent.resource(ResourceType.AUTHORIZATION_RESOURCE_SERVER).operation(operation).resourcePath(uriInfo)
                    .representation(ModelToRepresentation.toRepresentation(resourceServer, client)).success();
        }
    }
}
