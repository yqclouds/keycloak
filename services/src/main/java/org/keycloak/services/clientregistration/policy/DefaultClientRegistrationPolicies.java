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

package org.keycloak.services.clientregistration.policy;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.services.clientregistration.policy.impl.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientRegistrationPolicies {

    private static final String[] DEFAULT_ALLOWED_PROTOCOL_MAPPERS = {
            UserAttributeMapper.PROVIDER_ID,
            UserPropertyMapper.PROVIDER_ID,
            FullNameMapper.PROVIDER_ID,
            AddressMapper.PROVIDER_ID,
            new SHA256PairwiseSubMapper().getId()
    };

    public static void addDefaultPolicies(RealmModel realm) {
        String anonPolicyType = ClientRegistrationPolicyManager.getComponentTypeKey(RegistrationAuth.ANONYMOUS);
        String authPolicyType = ClientRegistrationPolicyManager.getComponentTypeKey(RegistrationAuth.AUTHENTICATED);
        List<ComponentModel> policies = realm.getComponents(realm.getId(), ClientRegistrationPolicy.class.getName());

        // Probably an issue if admin removes all policies intentionally...
        if (policies == null || policies.isEmpty()) {
            addAnonymousPolicies(realm, anonPolicyType);
            addAuthPolicies(realm, authPolicyType);
        }
    }

    private static ComponentModel createModelInstance(String name, RealmModel realm, String providerId, String policyType) {
        ComponentModel model = new ComponentModel();
        model.setName(name);
        model.setParentId(realm.getId());
        model.setProviderId(providerId);
        model.setProviderType(ClientRegistrationPolicy.class.getName());
        model.setSubType(policyType);
        return model;
    }

    private static void addAnonymousPolicies(RealmModel realm, String policyTypeKey) {
        ComponentModel trustedHostModel = createModelInstance("Trusted Hosts", realm, TrustedHostClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);

        // Not any trusted hosts by default
        trustedHostModel.getConfig().put(TrustedHostClientRegistrationPolicyFactory.TRUSTED_HOSTS, Collections.emptyList());
        trustedHostModel.getConfig().putSingle(TrustedHostClientRegistrationPolicyFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH, "true");
        trustedHostModel.getConfig().putSingle(TrustedHostClientRegistrationPolicyFactory.CLIENT_URIS_MUST_MATCH, "true");
        realm.addComponentModel(trustedHostModel);

        ComponentModel consentRequiredModel = createModelInstance("Consent Required", realm, ConsentRequiredClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);
        realm.addComponentModel(consentRequiredModel);

        ComponentModel scopeModel = createModelInstance("Full Scope Disabled", realm, ScopeClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);
        realm.addComponentModel(scopeModel);

        ComponentModel maxClientsModel = createModelInstance("Max Clients Limit", realm, MaxClientsClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);
        maxClientsModel.put(MaxClientsClientRegistrationPolicyFactory.MAX_CLIENTS, MaxClientsClientRegistrationPolicyFactory.DEFAULT_MAX_CLIENTS);
        realm.addComponentModel(maxClientsModel);

        addGenericPolicies(realm, policyTypeKey);
    }


    private static void addAuthPolicies(RealmModel realm, String policyTypeKey) {
        addGenericPolicies(realm, policyTypeKey);
    }

    private static void addGenericPolicies(RealmModel realm, String policyTypeKey) {
        ComponentModel protMapperModel = createModelInstance("Allowed Protocol Mapper Types", realm, ProtocolMappersClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);
        protMapperModel.getConfig().put(ProtocolMappersClientRegistrationPolicyFactory.ALLOWED_PROTOCOL_MAPPER_TYPES, Arrays.asList(DEFAULT_ALLOWED_PROTOCOL_MAPPERS));
        realm.addComponentModel(protMapperModel);

        ComponentModel clientTemplatesModel = createModelInstance("Allowed Client Scopes", realm, ClientScopesClientRegistrationPolicyFactory.PROVIDER_ID, policyTypeKey);
        clientTemplatesModel.getConfig().put(ClientScopesClientRegistrationPolicyFactory.ALLOWED_CLIENT_SCOPES, Collections.emptyList());
        clientTemplatesModel.put(ClientScopesClientRegistrationPolicyFactory.ALLOW_DEFAULT_SCOPES, true);
        realm.addComponentModel(clientTemplatesModel);
    }


}
