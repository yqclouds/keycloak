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

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.AdminRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/**
 * Base resource for managing users
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Protocol Mappers
 */
public class RealmProtocolMappersResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmProtocolMappersResource.class);

    protected RealmModel realm;

    protected ProtocolMapperContainerModel client;

    @Context
    protected KeycloakSession session;
    @Autowired
    private ProtocolMapperUtils protocolMapperUtils;

    @Autowired
    private AdminRoot adminRoot;

    public RealmProtocolMappersResource(RealmModel realm,
                                        ProtocolMapperContainerModel client) {
        this.realm = realm;
        this.client = client;
    }

    /**
     * Get mappers by name for a specific protocol
     */
    @GET
    @NoCache
    @Path("protocol/{protocol}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<ProtocolMapperRepresentation> getMappersPerProtocol(@PathParam("protocol") String protocol) {
        List<ProtocolMapperRepresentation> mappers = new LinkedList<>();
        for (ProtocolMapperModel mapper : client.getProtocolMappers()) {
            if (protocolMapperUtils.isEnabled(mapper) && mapper.getProtocol().equals(protocol))
                mappers.add(ModelToRepresentation.toRepresentation(mapper));
        }
        return mappers;
    }

    /**
     * Create a mapper
     */
    @Path("models")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createMapper(ProtocolMapperRepresentation rep) {
        ProtocolMapperModel model;
        try {
            model = RepresentationToModel.toModel(rep);
            validateModel(model);
            model = client.addProtocolMapper(model);
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Protocol mapper exists with same name");
        }

        return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(model.getId()).build()).build();
    }

    /**
     * Create multiple mappers
     */
    @Path("add-models")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public void createMapper(List<ProtocolMapperRepresentation> reps) {
        ProtocolMapperModel model;
        for (ProtocolMapperRepresentation rep : reps) {
            model = RepresentationToModel.toModel(rep);
            validateModel(model);
            client.addProtocolMapper(model);
        }
    }

    /**
     * Get mappers
     */
    @GET
    @NoCache
    @Path("models")
    @Produces(MediaType.APPLICATION_JSON)
    public List<ProtocolMapperRepresentation> getMappers() {
        List<ProtocolMapperRepresentation> mappers = new LinkedList<>();
        for (ProtocolMapperModel mapper : client.getProtocolMappers()) {
            if (protocolMapperUtils.isEnabled(mapper)) {
                mappers.add(ModelToRepresentation.toRepresentation(mapper));
            }
        }
        return mappers;
    }

    /**
     * Get mapper by id
     *
     * @param id Mapper id
     */
    @GET
    @NoCache
    @Path("models/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public ProtocolMapperRepresentation getMapperById(@PathParam("id") String id) {
        ProtocolMapperModel model = client.getProtocolMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        return ModelToRepresentation.toRepresentation(model);
    }

    /**
     * Update the mapper
     *
     * @param id Mapper id
     */
    @PUT
    @NoCache
    @Path("models/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public void update(@PathParam("id") String id, ProtocolMapperRepresentation rep) {
        ProtocolMapperModel model = client.getProtocolMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        model = RepresentationToModel.toModel(rep);

        validateModel(model);

        client.updateProtocolMapper(model);
    }

    /**
     * Delete the mapper
     *
     * @param id Mapper id
     */
    @DELETE
    @NoCache
    @Path("models/{id}")
    public void delete(@PathParam("id") String id) {
        ProtocolMapperModel model = client.getProtocolMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        client.removeProtocolMapper(model);
    }

    private void validateModel(ProtocolMapperModel model) {
        try {
            ProtocolMapper mapper = (ProtocolMapper) session.getSessionFactory().getProviderFactory(ProtocolMapper.class, model.getProtocolMapper());
            if (mapper != null) {
                mapper.validateConfig(realm, client, model);
            } else {
                throw new NotFoundException("ProtocolMapper provider not found");
            }
        } catch (ProtocolMapperConfigException ex) {
            LOG.error(ex.getMessage());
            Properties messages = adminRoot.getMessages(realm, Locale.getDefault().getLanguage());
            throw new ErrorResponseException(ex.getMessage(), MessageFormat.format(messages.getProperty(ex.getMessageKey(), ex.getMessage()), ex.getParameters()),
                    Response.Status.BAD_REQUEST);
        }
    }
}
