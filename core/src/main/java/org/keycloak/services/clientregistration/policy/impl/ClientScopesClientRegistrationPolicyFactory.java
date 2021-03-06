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

package org.keycloak.services.clientregistration.policy.impl;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientregistration.policy.AbstractClientRegistrationPolicyFactory;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("ClientScopesClientRegistrationPolicyFactory")
@ProviderFactory(id = "allowed-client-templates", providerClasses = ClientRegistrationPolicy.class)
public class ClientScopesClientRegistrationPolicyFactory extends AbstractClientRegistrationPolicyFactory {

    // Keeping the name for backwards compatibility
    public static final String PROVIDER_ID = "allowed-client-templates";
    public static final String ALLOWED_CLIENT_SCOPES = "allowed-client-scopes";
    public static final String ALLOW_DEFAULT_SCOPES = "allow-default-scopes";
    private List<ProviderConfigProperty> configProperties;

    @Override
    public ClientRegistrationPolicy create(ComponentModel model) {
        return new ClientScopesClientRegistrationPolicy(model);
    }

    @Override
    public String getHelpText() {
        return "When present, it allows to specify whitelist of client scopes, which will be allowed in representation of registered (or updated) client";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProps = new LinkedList<>();

        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ALLOWED_CLIENT_SCOPES);
        property.setLabel("allowed-client-scopes.label");
        property.setHelpText("allowed-client-scopes.tooltip");
        property.setType(ProviderConfigProperty.MULTIVALUED_LIST_TYPE);

        property.setOptions(getClientScopes());
        configProps.add(property);

        property = new ProviderConfigProperty();
        property.setName(ALLOW_DEFAULT_SCOPES);
        property.setLabel("allow-default-scopes.label");
        property.setHelpText("allow-default-scopes.tooltip");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(true);
        configProps.add(property);

        configProperties = configProps;
        return configProperties;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    private List<String> getClientScopes() {
        RealmModel realm = keycloakContext.getRealm();
        if (realm == null) {
            return Collections.emptyList();
        } else {
            List<ClientScopeModel> clientScopes = realm.getClientScopes();
            return clientScopes.stream().map(ClientScopeModel::getName).collect(Collectors.toList());
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
