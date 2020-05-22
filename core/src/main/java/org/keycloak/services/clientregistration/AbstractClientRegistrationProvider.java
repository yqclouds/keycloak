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

package org.keycloak.services.clientregistration;

import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyManager;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.validation.ValidationMessages;
import org.keycloak.validation.ClientValidationUtil;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public abstract class AbstractClientRegistrationProvider implements ClientRegistrationProvider {

    protected EventBuilder event;
    protected ClientRegistrationAuth auth;

    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private ModelToRepresentation modelToRepresentation;
    @Autowired
    private ClientValidationUtil clientValidationUtil;
    @Autowired
    private ClientRegistrationPolicyManager clientRegistrationPolicyManager;
    @Autowired
    private ClientRegistrationTokenUtils clientRegistrationTokenUtils;
    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private RealmProvider realmProvider;

    public ClientRepresentation create(ClientRegistrationContext context) {
        ClientRepresentation client = context.getClient();

        event.event(EventType.CLIENT_REGISTER);

        RegistrationAuth registrationAuth = auth.requireCreate(context);

        ValidationMessages validationMessages = new ValidationMessages();
        if (!context.validateClient(validationMessages)) {
            String errorCode = validationMessages.fieldHasError("redirectUris") ? ErrorCodes.INVALID_REDIRECT_URI : ErrorCodes.INVALID_CLIENT_METADATA;
            throw new ErrorResponseException(
                    errorCode,
                    validationMessages.getStringMessages(),
                    Response.Status.BAD_REQUEST
            );
        }

        try {
            RealmModel realm = keycloakContext.getRealm();
            ClientModel clientModel = new ClientManager(new RealmManager()).createClient(realm, client, true);

            if (clientModel.isServiceAccountsEnabled()) {
                new ClientManager(new RealmManager()).enableServiceAccount(clientModel);
            }

            if (Boolean.TRUE.equals(client.getAuthorizationServicesEnabled())) {
                representationToModel.createResourceServer(clientModel, true);
            }

            clientRegistrationPolicyManager.triggerAfterRegister(context, registrationAuth, clientModel);

            client = modelToRepresentation.toRepresentation(clientModel);

            client.setSecret(clientModel.getSecret());

            clientValidationUtil.validate(clientModel, true, c -> {
                throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "", Response.Status.BAD_REQUEST);
            });

            String registrationAccessToken = clientRegistrationTokenUtils.updateRegistrationAccessToken(clientModel, registrationAuth);
            client.setRegistrationAccessToken(registrationAccessToken);

            if (auth.isInitialAccessToken()) {
                ClientInitialAccessModel initialAccessModel = auth.getInitialAccessModel();
                realmProvider.decreaseRemainingCount(realm, initialAccessModel);
            }

            event.client(client.getClientId()).success();
            return client;
        } catch (ModelDuplicateException e) {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client Identifier in use", Response.Status.BAD_REQUEST);
        }
    }

    public ClientRepresentation get(ClientModel client) {
        event.event(EventType.CLIENT_INFO);

        auth.requireView(client);

        ClientRepresentation rep = modelToRepresentation.toRepresentation(client);
        if (client.getSecret() != null) {
            rep.setSecret(client.getSecret());
        }

        if (auth.isRegistrationAccessToken()) {
            String registrationAccessToken = clientRegistrationTokenUtils.updateTokenSignature(auth);
            rep.setRegistrationAccessToken(registrationAccessToken);
        }

        event.client(client.getClientId()).success();
        return rep;
    }

    public ClientRepresentation update(String clientId, ClientRegistrationContext context) {
        ClientRepresentation rep = context.getClient();

        event.event(EventType.CLIENT_UPDATE).client(clientId);

        ClientModel client = keycloakContext.getRealm().getClientByClientId(clientId);
        RegistrationAuth registrationAuth = auth.requireUpdate(context, client);

        if (!client.getClientId().equals(rep.getClientId())) {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client Identifier modified", Response.Status.BAD_REQUEST);
        }

        ValidationMessages validationMessages = new ValidationMessages();
        if (!context.validateClient(validationMessages)) {
            String errorCode = validationMessages.fieldHasError("redirectUris") ? ErrorCodes.INVALID_REDIRECT_URI : ErrorCodes.INVALID_CLIENT_METADATA;
            throw new ErrorResponseException(
                    errorCode,
                    validationMessages.getStringMessages(),
                    Response.Status.BAD_REQUEST
            );
        }

        RepresentationToModel.updateClient(rep, client);
        RepresentationToModel.updateClientProtocolMappers(rep, client);

        clientValidationUtil.validate(client, false, c -> {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, c.getError(), Response.Status.BAD_REQUEST);
        });

        rep = modelToRepresentation.toRepresentation(client);

        if (auth.isRegistrationAccessToken()) {
            String registrationAccessToken = clientRegistrationTokenUtils.updateRegistrationAccessToken(client, auth.getRegistrationAuth());
            rep.setRegistrationAccessToken(registrationAccessToken);
        }

        clientRegistrationPolicyManager.triggerAfterUpdate(context, registrationAuth, client);

        event.client(client.getClientId()).success();
        return rep;
    }

    public void delete(String clientId) {
        event.event(EventType.CLIENT_DELETE).client(clientId);

        ClientModel client = keycloakContext.getRealm().getClientByClientId(clientId);
        auth.requireDelete(client);

        if (new ClientManager(new RealmManager()).removeClient(keycloakContext.getRealm(), client)) {
            event.client(client.getClientId()).success();
        } else {
            throw new ForbiddenException();
        }
    }

    @Override
    public ClientRegistrationAuth getAuth() {
        return this.auth;
    }

    @Override
    public void setAuth(ClientRegistrationAuth auth) {
        this.auth = auth;
    }

    @Override
    public EventBuilder getEvent() {
        return event;
    }

    @Override
    public void setEvent(EventBuilder event) {
        this.event = event;
    }

    @Override
    public void close() {
    }

}
