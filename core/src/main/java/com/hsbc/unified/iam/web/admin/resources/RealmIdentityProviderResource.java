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
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.StripSecretsUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.*;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

/**
 * @author Pedro Igor
 * @resource Identity Providers
 */
public class RealmIdentityProviderResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmIdentityProviderResource.class);

    private final AdminPermissionEvaluator auth;
    private final RealmModel realm;
    private final IdentityProviderModel identityProviderModel;

    @Autowired
    private KeycloakContext keycloakContext;

    public RealmIdentityProviderResource(AdminPermissionEvaluator auth, RealmModel realm, IdentityProviderModel identityProviderModel) {
        this.realm = realm;
        this.identityProviderModel = identityProviderModel;
        this.auth = auth;
    }

    // return ID of IdentityProvider from realm based on internalId of this provider
    private static String getProviderIdByInternalId(RealmModel realm, String providerInternalId) {
        List<IdentityProviderModel> providerModels = realm.getIdentityProviders();
        for (IdentityProviderModel providerModel : providerModels) {
            if (providerModel.getInternalId().equals(providerInternalId)) {
                return providerModel.getAlias();
            }
        }

        return null;
    }

    // sets internalId to IdentityProvider based on alias
    private static void lookUpProviderIdByAlias(RealmModel realm, IdentityProviderRepresentation providerRep) {
        List<IdentityProviderModel> providerModels = realm.getIdentityProviders();
        for (IdentityProviderModel providerModel : providerModels) {
            if (providerModel.getAlias().equals(providerRep.getAlias())) {
                providerRep.setInternalId(providerModel.getInternalId());
                return;
            }
        }
        throw new javax.ws.rs.NotFoundException();
    }

    private void updateUsersAfterProviderAliasChange(List<UserModel> users, String oldProviderId, String newProviderId, RealmModel realm) {
        for (UserModel user : users) {
            FederatedIdentityModel federatedIdentity = userProvider.getFederatedIdentity(user, oldProviderId, realm);
            if (federatedIdentity != null) {
                // Remove old link first
                userProvider.removeFederatedIdentity(realm, user, oldProviderId);

                // And create new
                FederatedIdentityModel newFederatedIdentity = new FederatedIdentityModel(newProviderId, federatedIdentity.getUserId(), federatedIdentity.getUserName(),
                        federatedIdentity.getToken());
                userProvider.addFederatedIdentity(realm, user, newFederatedIdentity);
            }
        }
    }

    public static ManagementPermissionReference toMgmtRef(IdentityProviderModel model, AdminPermissionManagement permissions) {
        ManagementPermissionReference ref = new ManagementPermissionReference();
        ref.setEnabled(true);
        ref.setResource(permissions.idps().resource(model).getId());
        ref.setScopePermissions(permissions.idps().getPermissions(model));
        return ref;
    }

    /**
     * Get the identity provider
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public IdentityProviderRepresentation getIdentityProvider() {
        this.auth.realm().requireViewIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        IdentityProviderRepresentation rep = ModelToRepresentation.toRepresentation(realm, this.identityProviderModel);
        return StripSecretsUtils.strip(rep);
    }

    /**
     * Delete the identity provider
     */
    @DELETE
    @NoCache
    public Response delete() {
        this.auth.realm().requireManageIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        String alias = this.identityProviderModel.getAlias();
        this.realm.removeIdentityProviderByAlias(alias);

        Set<IdentityProviderMapperModel> mappers = this.realm.getIdentityProviderMappersByAlias(alias);
        for (IdentityProviderMapperModel mapper : mappers) {
            this.realm.removeIdentityProviderMapper(mapper);
        }

        return Response.noContent().build();
    }

    /**
     * Update the identity provider
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public Response update(IdentityProviderRepresentation providerRep) {
        this.auth.realm().requireManageIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        try {
            updateIdpFromRep(providerRep, realm);

            return Response.noContent().build();
        } catch (IllegalArgumentException e) {
            return ErrorResponse.error("Invalid request", BAD_REQUEST);
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Identity Provider " + providerRep.getAlias() + " already exists");
        }
    }

    @Autowired
    private UserProvider userProvider;
    @Autowired
    private RepresentationToModel representationToModel;

    private void updateIdpFromRep(IdentityProviderRepresentation providerRep, RealmModel realm) {
        String internalId = providerRep.getInternalId();
        String newProviderId = providerRep.getAlias();
        String oldProviderId = getProviderIdByInternalId(realm, internalId);

        if (oldProviderId == null) {
            lookUpProviderIdByAlias(realm, providerRep);
        }

        IdentityProviderModel updated = representationToModel.toModel(realm, providerRep);

        if (updated.getConfig() != null && ComponentRepresentation.SECRET_VALUE.equals(updated.getConfig().get("clientSecret"))) {
            updated.getConfig().put("clientSecret", identityProviderModel.getConfig() != null ? identityProviderModel.getConfig().get("clientSecret") : null);
        }

        realm.updateIdentityProvider(updated);

        if (oldProviderId != null && !oldProviderId.equals(newProviderId)) {

            // Admin changed the ID (alias) of identity provider. We must update all clients and users
            LOG.debug("Changing providerId in all clients and linked users. oldProviderId=" + oldProviderId + ", newProviderId=" + newProviderId);

            updateUsersAfterProviderAliasChange(userProvider.getUsers(realm, false), oldProviderId, newProviderId, realm);
        }
    }

    @Autowired
    private Map<String, IdentityProviderFactory> identityProviderFactories;

    private IdentityProviderFactory getIdentityProviderFactory() {
        return identityProviderFactories.get(identityProviderModel.getProviderId());
    }

    /**
     * Export public broker configuration for identity provider
     *
     * @param format Format to use
     */
    @GET
    @Path("export")
    @NoCache
    public Response export(@QueryParam("format") String format) {
        this.auth.realm().requireViewIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        try {
            IdentityProviderFactory factory = getIdentityProviderFactory();
            return factory.create(identityProviderModel).export(keycloakContext.getUri(), realm, format);
        } catch (Exception e) {
            return ErrorResponse.error("Could not export public broker configuration for identity provider [" + identityProviderModel.getProviderId() + "].", Response.Status.NOT_FOUND);
        }
    }

    @Autowired
    private List<IdentityProviderMapper> identityProviderMappers;

    /**
     * Get mapper types for identity provider
     */
    @GET
    @Path("mapper-types")
    @NoCache
    public Map<String, IdentityProviderMapperTypeRepresentation> getMapperTypes() {
        this.auth.realm().requireViewIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        Map<String, IdentityProviderMapperTypeRepresentation> types = new HashMap<>();
        for (IdentityProviderMapper mapper : identityProviderMappers) {
            for (String type : mapper.getCompatibleProviders()) {
                if (IdentityProviderMapper.ANY_PROVIDER.equals(type) || type.equals(identityProviderModel.getProviderId())) {
                    IdentityProviderMapperTypeRepresentation rep = new IdentityProviderMapperTypeRepresentation();
                    rep.setId(mapper.getId());
                    rep.setCategory(mapper.getDisplayCategory());
                    rep.setName(mapper.getDisplayType());
                    rep.setHelpText(mapper.getHelpText());
                    List<ProviderConfigProperty> configProperties = mapper.getConfigProperties();
                    for (ProviderConfigProperty prop : configProperties) {
                        ConfigPropertyRepresentation propRep = ModelToRepresentation.toRepresentation(prop);
                        rep.getProperties().add(propRep);
                    }
                    types.put(rep.getId(), rep);
                    break;
                }
            }
        }
        return types;
    }

    /**
     * Get mappers for identity provider
     */
    @GET
    @Path("mappers")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<IdentityProviderMapperRepresentation> getMappers() {
        this.auth.realm().requireViewIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        List<IdentityProviderMapperRepresentation> mappers = new LinkedList<>();
        for (IdentityProviderMapperModel model : realm.getIdentityProviderMappersByAlias(identityProviderModel.getAlias())) {
            mappers.add(ModelToRepresentation.toRepresentation(model));
        }
        return mappers;
    }

    /**
     * Add a mapper to identity provider
     */
    @POST
    @Path("mappers")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addMapper(IdentityProviderMapperRepresentation mapper) {
        this.auth.realm().requireManageIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        IdentityProviderMapperModel model = RepresentationToModel.toModel(mapper);
        try {
            model = realm.addIdentityProviderMapper(model);
        } catch (Exception e) {
            return ErrorResponse.error("Failed to add mapper '" + model.getName() + "' to identity provider [" + identityProviderModel.getProviderId() + "].", Response.Status.BAD_REQUEST);
        }

        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(model.getId()).build()).build();
    }

    /**
     * Get mapper by id for the identity provider
     */
    @GET
    @NoCache
    @Path("mappers/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public IdentityProviderMapperRepresentation getMapperById(@PathParam("id") String id) {
        this.auth.realm().requireViewIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        IdentityProviderMapperModel model = realm.getIdentityProviderMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        return ModelToRepresentation.toRepresentation(model);
    }

    /**
     * Update a mapper for the identity provider
     *
     * @param id Mapper id
     */
    @PUT
    @NoCache
    @Path("mappers/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public void update(@PathParam("id") String id, IdentityProviderMapperRepresentation rep) {
        this.auth.realm().requireManageIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        IdentityProviderMapperModel model = realm.getIdentityProviderMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        model = RepresentationToModel.toModel(rep);
        realm.updateIdentityProviderMapper(model);
    }

    /**
     * Delete a mapper for the identity provider
     *
     * @param id Mapper id
     */
    @DELETE
    @NoCache
    @Path("mappers/{id}")
    public void delete(@PathParam("id") String id) {
        this.auth.realm().requireManageIdentityProviders();

        if (identityProviderModel == null) {
            throw new javax.ws.rs.NotFoundException();
        }

        IdentityProviderMapperModel model = realm.getIdentityProviderMapperById(id);
        if (model == null) throw new NotFoundException("Model not found");
        realm.removeIdentityProviderMapper(model);
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     */
    @Path("management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions() {
        this.auth.realm().requireViewIdentityProviders();

        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        if (!permissions.idps().isPermissionsEnabled(identityProviderModel)) {
            return new ManagementPermissionReference();
        }
        return toMgmtRef(identityProviderModel, permissions);
    }

    /**
     * Return object stating whether client Authorization permissions have been initialized or not and a reference
     *
     * @return initialized manage permissions reference
     */
    @Path("management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(ManagementPermissionReference ref) {
        this.auth.realm().requireManageIdentityProviders();
        AdminPermissionManagement permissions = AdminPermissions.management(realm);
        permissions.idps().setPermissionsEnabled(identityProviderModel, ref.isEnabled());
        if (ref.isEnabled()) {
            return toMgmtRef(identityProviderModel, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }
}
