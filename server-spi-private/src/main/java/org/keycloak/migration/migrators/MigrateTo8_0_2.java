/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.migration.migrators;

import org.jboss.logging.Logger;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.LinkedList;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class MigrateTo8_0_2 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("8.0.2");

    private static final Logger LOG = Logger.getLogger(MigrateTo8_0_2.class);

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

    @Override
    public void migrate(KeycloakSession session) {
        session.realms().getRealms().forEach(this::migrateAuthenticationFlowsWithAlternativeRequirements);
    }

    @Override
    public void migrateImport(KeycloakSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateAuthenticationFlowsWithAlternativeRequirements(realm);
    }


    protected void migrateAuthenticationFlowsWithAlternativeRequirements(RealmModel realm) {
        for (AuthenticationFlowModel flow : realm.getAuthenticationFlows()) {

            boolean alternativeFound = false;
            boolean requiredFound = false;
            for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutions(flow.getId())) {
                switch (execution.getRequirement()) {
                    case REQUIRED:
                    case CONDITIONAL:
                        requiredFound = true;
                        break;
                    case ALTERNATIVE:
                        alternativeFound = true;
                        break;
                }
            }

            // This flow contains some REQUIRED and ALTERNATIVE at the same level. We will migrate ALTERNATIVES to separate subflows
            // to try to preserve same behaviour as in previous versions
            if (requiredFound && alternativeFound) {

                // Suffix used just to avoid name conflicts
                int suffix = 0;
                LinkedList<AuthenticationExecutionModel> alternativesToMigrate = new LinkedList<>();
                for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutions(flow.getId())) {
                    if (AuthenticationExecutionModel.Requirement.ALTERNATIVE.equals(execution.getRequirement())) {
                        alternativesToMigrate.add(execution);
                    }

                    // If we have some REQUIRED then ALTERNATIVE and then REQUIRED/CONDITIONAL, we migrate the alternatives to the new subflow.
                    if (AuthenticationExecutionModel.Requirement.REQUIRED.equals(execution.getRequirement()) ||
                            AuthenticationExecutionModel.Requirement.CONDITIONAL.equals(execution.getRequirement())) {
                        if (!alternativesToMigrate.isEmpty()) {
                            migrateAlternatives(realm, flow, alternativesToMigrate, suffix);
                            suffix += 1;
                            alternativesToMigrate.clear();
                        }
                    }
                }

                if (!alternativesToMigrate.isEmpty()) {
                    migrateAlternatives(realm, flow, alternativesToMigrate, suffix);
                }
            }
        }
    }


    private void migrateAlternatives(RealmModel realm, AuthenticationFlowModel parentFlow,
                                     LinkedList<AuthenticationExecutionModel> alternativesToMigrate, int suffix) {
        LOG.debugf("Migrating %d ALTERNATIVE executions in the flow '%s' of realm '%s' to separate subflow", alternativesToMigrate.size(),
                parentFlow.getAlias(), realm.getName());

        AuthenticationFlowModel newFlow = new AuthenticationFlowModel();
        newFlow.setTopLevel(false);
        newFlow.setBuiltIn(parentFlow.isBuiltIn());
        newFlow.setAlias(parentFlow.getAlias() + " - Alternatives - " + suffix);
        newFlow.setDescription("Subflow of " + parentFlow.getAlias() + " with alternative executions");
        newFlow.setProviderId("basic-flow");
        newFlow = realm.addAuthenticationFlow(newFlow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setParentFlow(parentFlow.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
        execution.setFlowId(newFlow.getId());
        // Use same priority as the first ALTERNATIVE as new execution will defacto replace it in the parent flow
        execution.setPriority(alternativesToMigrate.getFirst().getPriority());
        execution.setAuthenticatorFlow(true);
        realm.addAuthenticatorExecution(execution);

        int priority = 0;
        for (AuthenticationExecutionModel ex : alternativesToMigrate) {
            priority += 10;
            ex.setParentFlow(newFlow.getId());
            ex.setPriority(priority);
            realm.updateAuthenticatorExecution(ex);
        }
    }

}
