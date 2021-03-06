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
package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.ClientConnection;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.component.SubComponentFactory;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.StripSecretsUtils;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.ComponentTypeRepresentation;
import org.keycloak.representations.idm.ConfigPropertyRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.AdminRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.*;

/**
 * Base path for managing components under this realm.
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/components",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmComponentsResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmComponentsResource.class);

    protected RealmModel realm;
    @Context
    protected ClientConnection clientConnection;
    @Autowired
    private KeycloakContext keycloakContext;
    @Context
    protected HttpHeaders headers;

    @Autowired
    private ModelToRepresentation modelToRepresentation;
    @Autowired
    private RepresentationToModel representationToModel;

    public RealmComponentsResource(RealmModel realm) {
        this.realm = realm;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<ComponentRepresentation> getComponents(@QueryParam("parent") String parent,
                                                       @QueryParam("type") String type,
                                                       @QueryParam("name") String name) {
        List<ComponentModel> components;
        if (parent == null && type == null) {
            components = realm.getComponents();
        } else if (type == null) {
            components = realm.getComponents(parent);
        } else if (parent == null) {
            components = realm.getComponents(realm.getId(), type);
        } else {
            components = realm.getComponents(parent, type);
        }
        List<ComponentRepresentation> reps = new LinkedList<>();
        for (ComponentModel component : components) {
            if (name != null && !name.equals(component.getName())) continue;
            ComponentRepresentation rep = null;
            try {
                rep = modelToRepresentation.toRepresentation(component, false);
            } catch (Exception e) {
                LOG.error("Failed to get component list for component model" + component.getName() + "of realm " + realm.getName());
                rep = ModelToRepresentation.toRepresentationWithoutConfig(component);
            }
            reps.add(rep);
        }
        return reps;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response create(ComponentRepresentation rep) {
        try {
            ComponentModel model = representationToModel.toModel(rep);
            if (model.getParentId() == null) model.setParentId(realm.getId());

            model = realm.addComponentModel(model);

            return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(model.getId()).build()).build();
        } catch (ComponentValidationException e) {
            return localizedErrorResponse(e);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e);
        }
    }

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ComponentRepresentation getComponent(@PathParam("id") String id) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        return modelToRepresentation.toRepresentation(model, false);
    }

    @Autowired
    private StripSecretsUtils stripSecretsUtils;

    @PUT
    @Path("{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateComponent(@PathParam("id") String id, ComponentRepresentation rep) {
        try {
            ComponentModel model = realm.getComponent(id);
            if (model == null) {
                throw new NotFoundException("Could not find component");
            }
            representationToModel.updateComponent(rep, model, false);
            realm.updateComponent(model);
            return Response.noContent().build();
        } catch (ComponentValidationException e) {
            return localizedErrorResponse(e);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException();
        }
    }

    @DELETE
    @Path("{id}")
    public void removeComponent(@PathParam("id") String id) {
        ComponentModel model = realm.getComponent(id);
        if (model == null) {
            throw new NotFoundException("Could not find component");
        }
        realm.removeComponent(model);
    }

    @Autowired
    private AdminRoot adminRoot;

    private Response localizedErrorResponse(ComponentValidationException cve) {
        Properties messages = adminRoot.getMessages(realm, Locale.getDefault().getLanguage(), "admin-messages", "messages");

        Object[] localizedParameters = cve.getParameters() == null ? null : Arrays.stream(cve.getParameters()).map((Object parameter) -> {

            if (parameter instanceof String) {
                String paramStr = (String) parameter;
                return messages.getProperty(paramStr, paramStr);
            } else {
                return parameter;
            }

        }).toArray();

        String message = MessageFormat.format(messages.getProperty(cve.getMessage(), cve.getMessage()), localizedParameters);
        return ErrorResponse.error(message, Response.Status.BAD_REQUEST);
    }

    @Autowired
    private List<ComponentFactory> componentFactories;

    /**
     * List of subcomponent types that are available to configure for a particular parent component.
     */
    @GET
    @Path("{id}/sub-component-types")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<ComponentTypeRepresentation> getSubcomponentConfig(@PathParam("id") String parentId, @QueryParam("type") String subtype) {
        ComponentModel parent = realm.getComponent(parentId);
        if (parent == null) {
            throw new NotFoundException("Could not find parent component");
        }
        if (subtype == null) {
            throw new BadRequestException("must specify a subtype");
        }
        Class<? extends Provider> providerClass = null;
        try {
            providerClass = (Class<? extends Provider>) Class.forName(subtype);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        List<ComponentTypeRepresentation> subcomponents = new LinkedList<>();
        for (ComponentFactory componentFactory : componentFactories) {
            ComponentTypeRepresentation rep = new ComponentTypeRepresentation();
            rep.setId(componentFactory.getId());

            rep.setHelpText(componentFactory.getHelpText());
            List<ProviderConfigProperty> props = null;
            Map<String, Object> metadata = null;
            if (componentFactory instanceof SubComponentFactory) {
                props = ((SubComponentFactory) componentFactory).getConfigProperties(realm, parent);
                metadata = ((SubComponentFactory) componentFactory).getTypeMetadata(realm, parent);

            } else {
                props = componentFactory.getConfigProperties();
                metadata = componentFactory.getTypeMetadata();
            }

            List<ConfigPropertyRepresentation> propReps = ModelToRepresentation.toRepresentation(props);
            rep.setProperties(propReps);
            rep.setMetadata(metadata);
            subcomponents.add(rep);
        }
        return subcomponents;
    }
}
