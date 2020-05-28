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

import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.admin.AuthorizationService;
import org.keycloak.events.Errors;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.validation.ClientValidator;
import org.keycloak.services.validation.PairwiseClientValidator;
import org.keycloak.services.validation.ValidationMessages;
import org.keycloak.validation.ClientValidationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static java.lang.Boolean.TRUE;

/**
 * Base resource class for managing a realm's clients.
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/clients",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmClientsResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmClientsResource.class);

    protected RealmModel realm;
    @Context
    protected KeycloakSession session;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public RealmClientsResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT);
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    /**
     * Get clients belonging to the realm
     * <p>
     * Returns a list of clients belonging to the realm
     *
     * @param clientId     filter by clientId
     * @param viewableOnly filter clients that cannot be viewed in full by admin
     * @param search       whether this is a search query or a getClientById query
     * @param firstResult  the first result
     * @param maxResults   the max results to return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<ClientRepresentation> getClients(@QueryParam("clientId") String clientId,
                                                 @QueryParam("viewableOnly") @DefaultValue("false") boolean viewableOnly,
                                                 @QueryParam("search") @DefaultValue("false") boolean search,
                                                 @QueryParam("first") Integer firstResult,
                                                 @QueryParam("max") Integer maxResults) {
        List<ClientRepresentation> rep = new ArrayList<>();

        if (clientId == null || clientId.trim().equals("")) {
            List<ClientModel> clientModels = realm.getClients(firstResult, maxResults);
            auth.clients().requireList();
            boolean view = auth.clients().canView();
            for (ClientModel clientModel : clientModels) {
                if (view || auth.clients().canView(clientModel)) {
                    ClientRepresentation representation = modelToRepresentation.toRepresentation(clientModel);
                    rep.add(representation);
                    representation.setAccess(auth.clients().getAccess(clientModel));
                } else if (!viewableOnly && auth.clients().canView(clientModel)) {
                    ClientRepresentation client = new ClientRepresentation();
                    client.setId(clientModel.getId());
                    client.setClientId(clientModel.getClientId());
                    client.setDescription(clientModel.getDescription());
                    rep.add(client);
                }
            }
        } else {
            List<ClientModel> clientModels = Collections.emptyList();
            if (search) {
                clientModels = realm.searchClientByClientId(clientId, firstResult, maxResults);
            } else {
                ClientModel client = realm.getClientByClientId(clientId);
                if (client != null) {
                    clientModels = Collections.singletonList(client);
                }
            }
            if (clientModels != null) {
                for (ClientModel clientModel : clientModels) {
                    if (auth.clients().canView(clientModel)) {
                        ClientRepresentation representation = modelToRepresentation.toRepresentation(clientModel);
                        representation.setAccess(auth.clients().getAccess(clientModel));
                        rep.add(representation);
                    } else if (!viewableOnly && auth.clients().canView(clientModel)) {
                        ClientRepresentation client = new ClientRepresentation();
                        client.setId(clientModel.getId());
                        client.setClientId(clientModel.getClientId());
                        client.setDescription(clientModel.getDescription());
                        rep.add(client);
                    }
                }
            }
        }
        return rep;
    }

    private AuthorizationService getAuthorizationService(ClientModel clientModel) {
        return new AuthorizationService(clientModel, auth, adminEvent);
    }

    @Autowired
    private ClientValidationUtil clientValidationUtil;
    @Autowired
    private PairwiseClientValidator pairwiseClientValidator;
    @Autowired
    private AdminRoot adminRoot;
    @Autowired
    private ClientManager clientManager;

    /**
     * Create a new client
     * <p>
     * Client's client_id must be unique!
     *
     * @param rep
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createClient(final ClientRepresentation rep) {
        auth.clients().requireManage();

        ValidationMessages validationMessages = new ValidationMessages();
        if (!ClientValidator.validate(rep, validationMessages) || !pairwiseClientValidator.validate(rep, validationMessages)) {
            Properties messages = adminRoot.getMessages(realm, auth.adminAuth().getToken().getLocale());
            throw new ErrorResponseException(
                    validationMessages.getStringMessages(),
                    validationMessages.getStringMessages(messages),
                    Response.Status.BAD_REQUEST
            );
        }

        try {
            ClientModel clientModel = clientManager.createClient(realm, rep, true);

            if (TRUE.equals(rep.isServiceAccountsEnabled())) {
                UserModel serviceAccount = session.users().getServiceAccount(clientModel);

                if (serviceAccount == null) {
                    new ClientManager(new RealmFacadeImpl()).enableServiceAccount(clientModel);
                }
            }

            adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), clientModel.getId()).representation(rep).success();

            if (TRUE.equals(rep.getAuthorizationServicesEnabled())) {
                AuthorizationService authorizationService = getAuthorizationService(clientModel);

                authorizationService.enable(true);

                ResourceServerRepresentation authorizationSettings = rep.getAuthorizationSettings();

                if (authorizationSettings != null) {
                    authorizationService.resourceServer().importSettings(authorizationSettings);
                }
            }

            clientValidationUtil.validate(clientModel, true, c -> {
                session.getTransactionManager().setRollbackOnly();
                throw new ErrorResponseException(Errors.INVALID_INPUT, c.getError(), Response.Status.BAD_REQUEST);
            });

            return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(clientModel.getId()).build()).build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Client " + rep.getClientId() + " already exists");
        }
    }

    /**
     * Base path for managing a specific client.
     *
     * @param id id of client (not client-id)
     * @return
     */
    @Path("{id}")
    public RealmClientResource getClient(final @PathParam("id") String id) {

        ClientModel clientModel = realm.getClientById(id);
        if (clientModel == null) {
            // we do this to make sure somebody can't phish ids
            if (auth.clients().canList()) throw new NotFoundException("Could not find client");
            else throw new ForbiddenException();
        }

        session.getContext().setClient(clientModel);

        RealmClientResource clientResource = new RealmClientResource(realm, auth, clientModel, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(clientResource);
        return clientResource;
    }

}