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
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.ComponentTypeRepresentation;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/client-registration-policy",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmClientRegistrationPolicyResource {
    @Autowired
    private List<ClientRegistrationPolicyFactory> clientRegistrationPolicyFactories;

    /**
     * Base path for retrieve providers with the configProperties properly filled
     */
    @Path("providers")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<ComponentTypeRepresentation> getProviders() {
        return clientRegistrationPolicyFactories.stream().map((ProviderFactory factory) -> {
            ClientRegistrationPolicyFactory clientRegFactory = (ClientRegistrationPolicyFactory) factory;
            List<ProviderConfigProperty> configProps = clientRegFactory.getConfigProperties();

            ComponentTypeRepresentation rep = new ComponentTypeRepresentation();
            rep.setId(clientRegFactory.getId());
            rep.setHelpText(clientRegFactory.getHelpText());
            rep.setProperties(ModelToRepresentation.toRepresentation(configProps));
            return rep;

        }).collect(Collectors.toList());
    }
}
