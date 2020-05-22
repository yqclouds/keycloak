package org.keycloak.authorization.policy.provider.client;

import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.function.BiFunction;

public class ClientPolicyProvider implements PolicyProvider {

    private final BiFunction<PolicyModel, AuthorizationProvider, ClientPolicyRepresentation> representationFunction;

    public ClientPolicyProvider(BiFunction<PolicyModel, AuthorizationProvider, ClientPolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public void evaluate(Evaluation evaluation) {
        ClientPolicyRepresentation representation = representationFunction.apply(evaluation.getPolicy(), evaluation.getAuthorizationProvider());
        RealmModel realm = keycloakContext.getRealm();
        EvaluationContext context = evaluation.getContext();

        for (String client : representation.getClients()) {
            ClientModel clientModel = realm.getClientById(client);

            if (context.getAttributes().containsValue("kc.client.id", clientModel.getClientId())) {
                evaluation.grant();
                return;
            }
        }
    }

    @Override
    public void close() {

    }
}
