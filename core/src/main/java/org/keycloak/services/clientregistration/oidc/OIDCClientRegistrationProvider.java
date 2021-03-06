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
package org.keycloak.services.clientregistration.oidc;

import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.mappers.AbstractPairwiseSubMapper;
import org.keycloak.protocol.oidc.mappers.PairwiseSubMapperHelper;
import org.keycloak.protocol.oidc.mappers.SHA256PairwiseSubMapper;
import org.keycloak.protocol.oidc.utils.SubjectType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientregistration.AbstractClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationException;
import org.keycloak.services.clientregistration.ErrorCodes;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCClientRegistrationProvider extends AbstractClientRegistrationProvider {
    @Autowired
    private DescriptionConverter descriptionConverter;
    @Autowired
    private KeycloakContext keycloakContext;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createOIDC(OIDCClientRepresentation clientOIDC) {
        if (clientOIDC.getClientId() != null) {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client Identifier included", Response.Status.BAD_REQUEST);
        }

        try {
            ClientRepresentation client = descriptionConverter.toInternal(clientOIDC);
            List<String> grantTypes = clientOIDC.getGrantTypes();

            if (grantTypes != null && grantTypes.contains(OAuth2Constants.UMA_GRANT_TYPE)) {
                client.setAuthorizationServicesEnabled(true);
            }

            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(client, this, clientOIDC);
            client = create(oidcContext);

            ClientModel clientModel = keycloakContext.getRealm().getClientByClientId(client.getClientId());
            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            URI uri = keycloakContext.getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
            clientOIDC = descriptionConverter.toExternalResponse(client, uri);
            clientOIDC.setClientIdIssuedAt(Time.currentTime());
            return Response.created(uri).entity(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
//            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOIDC(@PathParam("clientId") String clientId) {
        ClientModel client = keycloakContext.getRealm().getClientByClientId(clientId);

        ClientRepresentation clientRepresentation = get(client);

        OIDCClientRepresentation clientOIDC = descriptionConverter.toExternalResponse(clientRepresentation, keycloakContext.getUri().getRequestUri());
        return Response.ok(clientOIDC).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateOIDC(@PathParam("clientId") String clientId, OIDCClientRepresentation clientOIDC) {
        try {
            ClientRepresentation client = descriptionConverter.toInternal(clientOIDC);
            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(client, this, clientOIDC);
            client = update(clientId, oidcContext);

            ClientModel clientModel = keycloakContext.getRealm().getClientByClientId(client.getClientId());
            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            URI uri = keycloakContext.getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
            clientOIDC = descriptionConverter.toExternalResponse(client, uri);
            return Response.ok(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
//            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @DELETE
    @Path("{clientId}")
    public void deleteOIDC(@PathParam("clientId") String clientId) {
        delete(clientId);
    }

    private void updatePairwiseSubMappers(ClientModel clientModel, SubjectType subjectType, String sectorIdentifierUri) {
        if (subjectType == SubjectType.PAIRWISE) {

            // See if we have existing pairwise mapper and update it. Otherwise create new
            AtomicBoolean foundPairwise = new AtomicBoolean(false);

            clientModel.getProtocolMappers().stream().filter((ProtocolMapperModel mapping) -> {
                if (mapping.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX)) {
                    foundPairwise.set(true);
                    return true;
                } else {
                    return false;
                }
            }).forEach((ProtocolMapperModel mapping) -> {
                PairwiseSubMapperHelper.setSectorIdentifierUri(mapping, sectorIdentifierUri);
                clientModel.updateProtocolMapper(mapping);
            });

            // We don't have existing pairwise mapper. So create new
            if (!foundPairwise.get()) {
                ProtocolMapperRepresentation newPairwise = SHA256PairwiseSubMapper.createPairwiseMapper(sectorIdentifierUri, null);
                clientModel.addProtocolMapper(RepresentationToModel.toModel(newPairwise));
            }

        } else {
            // Rather find and remove all pairwise mappers
            clientModel.getProtocolMappers().stream().filter((ProtocolMapperModel mapperRep) -> {
                return mapperRep.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX);
            }).forEach((ProtocolMapperModel mapping) -> {
                clientModel.getProtocolMappers().remove(mapping);
            });
        }
    }

    private void updateClientRepWithProtocolMappers(ClientModel clientModel, ClientRepresentation rep) {
        List<ProtocolMapperRepresentation> mappings = new LinkedList<>();
        for (ProtocolMapperModel model : clientModel.getProtocolMappers()) {
            mappings.add(ModelToRepresentation.toRepresentation(model));
        }
        rep.setProtocolMappers(mappings);
    }
}
