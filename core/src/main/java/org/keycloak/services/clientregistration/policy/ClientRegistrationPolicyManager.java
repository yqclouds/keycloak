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
import org.keycloak.events.Details;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientRegistrationPolicyManager {

    private static final Logger LOG = LoggerFactory.getLogger(ClientRegistrationPolicyManager.class);

    public void triggerBeforeRegister(ClientRegistrationContext context, RegistrationAuth authType) throws ClientRegistrationPolicyException {
        triggerPolicies(context.getProvider(), authType, "before register client", (ClientRegistrationPolicy policy) -> {

            policy.beforeRegister(context);

        });
    }


    public void triggerAfterRegister(ClientRegistrationContext context, RegistrationAuth authType, ClientModel client) {
        try {
            triggerPolicies(context.getProvider(), authType, "after register client " + client.getClientId(), (ClientRegistrationPolicy policy) -> {

                policy.afterRegister(context, client);

            });
        } catch (ClientRegistrationPolicyException crpe) {
            throw new IllegalStateException(crpe);
        }
    }


    public void triggerBeforeUpdate(ClientRegistrationContext context, RegistrationAuth authType, ClientModel client) throws ClientRegistrationPolicyException {
        triggerPolicies(context.getProvider(), authType, "before update client " + client.getClientId(), (ClientRegistrationPolicy policy) -> {

            policy.beforeUpdate(context, client);

        });
    }

    public void triggerAfterUpdate(ClientRegistrationContext context, RegistrationAuth authType, ClientModel client) {
        try {
            triggerPolicies(context.getProvider(), authType, "after update client " + client.getClientId(), (ClientRegistrationPolicy policy) -> {

                policy.afterUpdate(context, client);

            });
        } catch (ClientRegistrationPolicyException crpe) {
            throw new IllegalStateException(crpe);
        }
    }

    public void triggerBeforeView(ClientRegistrationProvider provider, RegistrationAuth authType, ClientModel client) throws ClientRegistrationPolicyException {
        triggerPolicies(provider, authType, "before view client " + client.getClientId(), (ClientRegistrationPolicy policy) -> {

            policy.beforeView(provider, client);

        });
    }

    public void triggerBeforeRemove(ClientRegistrationProvider provider, RegistrationAuth authType, ClientModel client) throws ClientRegistrationPolicyException {
        triggerPolicies(provider, authType, "before delete client " + client.getClientId(), (ClientRegistrationPolicy policy) -> {

            policy.beforeDelete(provider, client);

        });
    }

    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private Map<ComponentModel, ClientRegistrationPolicy> clientRegistrationPolicies;

    private void triggerPolicies(ClientRegistrationProvider provider, RegistrationAuth authType, String opDescription, ClientRegOperation op) throws ClientRegistrationPolicyException {
        RealmModel realm = keycloakContext.getRealm();

        String policyTypeKey = getComponentTypeKey(authType);
        List<ComponentModel> policyModels = realm.getComponents(realm.getId(), ClientRegistrationPolicy.class.getName());

        policyModels = policyModels.stream().filter((ComponentModel model) -> {

            return policyTypeKey.equals(model.getSubType());

        }).collect(Collectors.toList());

        for (ComponentModel policyModel : policyModels) {
            ClientRegistrationPolicy policy = clientRegistrationPolicies.get(policyModel);
            if (policy == null) {
                throw new ClientRegistrationPolicyException("PolicyModel of type '" + policyModel.getProviderId() + "' not found");
            }

            if (LOG.isTraceEnabled()) {
                LOG.trace("Running policy '%s' %s", policyModel.getName(), opDescription);
            }

            try {
                op.run(policy);
            } catch (ClientRegistrationPolicyException crpe) {
                provider.getEvent().detail(Details.CLIENT_REGISTRATION_POLICY, policyModel.getName());
                crpe.setPolicyModel(policyModel);
//                ServicesLogger.LOGGER.clientRegistrationRequestRejected(opDescription, crpe.getMessage());
                throw crpe;
            }
        }
    }

    public static String getComponentTypeKey(RegistrationAuth authType) {
        return authType.toString().toLowerCase();
    }

    private interface ClientRegOperation {

        void run(ClientRegistrationPolicy policy) throws ClientRegistrationPolicyException;

    }
}
