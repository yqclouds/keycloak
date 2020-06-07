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
import org.jboss.resteasy.plugins.providers.multipart.InputPart;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.StripSecretsUtils;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.utils.ReservedCharValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/identity-provider",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmIdentityProvidersResource {

    private final RealmModel realm;
    @Autowired
    private KeycloakContext keycloakContext;

    public RealmIdentityProvidersResource(RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Get identity providers
     */
    @Path("/providers/{provider_id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response getIdentityProviders(@PathParam("provider_id") String providerId) {
        IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);
        if (providerFactory != null) {
            return Response.ok(providerFactory).build();
        }
        return Response.status(BAD_REQUEST).build();
    }

    /**
     * Import identity provider from uploaded JSON file
     */
    @POST
    @Path("import-config")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> importFrom(MultipartFormDataInput input) throws IOException {
        Map<String, List<InputPart>> formDataMap = input.getFormDataMap();
        if (!(formDataMap.containsKey("providerId") && formDataMap.containsKey("file"))) {
            throw new BadRequestException();
        }
        String providerId = formDataMap.get("providerId").get(0).getBodyAsString();
        InputPart file = formDataMap.get("file").get(0);
        InputStream inputStream = file.getBody(InputStream.class, null);
        IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);
        return (Map<String, String>) providerFactory.parseConfig(inputStream);
    }

    @Autowired
    private HttpClientProvider httpClientProvider;

    /**
     * Import identity provider from JSON body
     *
     * @param data JSON body
     */
    @POST
    @Path("import-config")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> importFrom(Map<String, Object> data) throws IOException {
        if (!(data.containsKey("providerId") && data.containsKey("fromUrl"))) {
            throw new BadRequestException();
        }

        ReservedCharValidator.validate((String) data.get("alias"));

        String providerId = data.get("providerId").toString();
        String from = data.get("fromUrl").toString();
        InputStream inputStream = httpClientProvider.get(from);
        try {
            IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);
            Map<String, String> config;
            config = providerFactory.parseConfig(inputStream);
            return config;
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * Get identity providers
     */
    @GET
    @Path("instances")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<IdentityProviderRepresentation> getIdentityProviders() {
        List<IdentityProviderRepresentation> representations = new ArrayList<IdentityProviderRepresentation>();

        for (IdentityProviderModel identityProviderModel : realm.getIdentityProviders()) {
            representations.add(StripSecretsUtils.strip(ModelToRepresentation.toRepresentation(realm, identityProviderModel)));
        }
        return representations;
    }

    @Autowired
    private RepresentationToModel representationToModel;

    /**
     * Create a new identity provider
     *
     * @param representation JSON body
     */
    @POST
    @Path("instances")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response create(IdentityProviderRepresentation representation) {
        ReservedCharValidator.validate(representation.getAlias());

        try {
            IdentityProviderModel identityProvider = representationToModel.toModel(realm, representation);
            this.realm.addIdentityProvider(identityProvider);

            representation.setInternalId(identityProvider.getInternalId());

            return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(representation.getAlias()).build()).build();
        } catch (IllegalArgumentException e) {
            return ErrorResponse.error("Invalid request", BAD_REQUEST);
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Identity Provider " + representation.getAlias() + " already exists");
        }
    }

    @Path("instances/{alias}")
    public RealmIdentityProviderResource getIdentityProvider(@PathParam("alias") String alias) {
        IdentityProviderModel identityProviderModel = null;

        for (IdentityProviderModel storedIdentityProvider : this.realm.getIdentityProviders()) {
            if (storedIdentityProvider.getAlias().equals(alias)
                    || storedIdentityProvider.getInternalId().equals(alias)) {
                identityProviderModel = storedIdentityProvider;
            }
        }

        RealmIdentityProviderResource identityProviderResource = new RealmIdentityProviderResource(realm, identityProviderModel);
        ResteasyProviderFactory.getInstance().injectProperties(identityProviderResource);

        return identityProviderResource;
    }

    private IdentityProviderFactory getProviderFactorytById(String providerId) {
        List<IdentityProviderFactory> allProviders = getProviderFactories();
        for (ProviderFactory providerFactory : allProviders) {
            if (providerFactory.getId().equals(providerId)) {
                return (IdentityProviderFactory) providerFactory;
            }
        }

        return null;
    }

    @Autowired
    private List<IdentityProviderFactory> identityProviderFactories;

    private List<IdentityProviderFactory> getProviderFactories() {
        return identityProviderFactories;
    }
}