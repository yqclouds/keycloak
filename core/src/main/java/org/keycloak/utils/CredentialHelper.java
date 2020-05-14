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

package org.keycloak.utils;

import com.hsbc.unified.iam.core.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.UserCredentialModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * used to set an execution a state based on type.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CredentialHelper {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialHelper.class);

    public static void setRequiredCredential(KeycloakSession session, String type, RealmModel realm) {
        AuthenticationExecutionRequirement requirement = AuthenticationExecutionRequirement.REQUIRED;
        setOrReplaceAuthenticationRequirement(session, realm, type, requirement, null);
    }

    public static void setAlternativeCredential(KeycloakSession session, String type, RealmModel realm) {
        AuthenticationExecutionRequirement requirement = AuthenticationExecutionRequirement.ALTERNATIVE;
        setOrReplaceAuthenticationRequirement(session, realm, type, requirement, null);
    }

    public static void setOrReplaceAuthenticationRequirement(KeycloakSession session, RealmModel realm, String type, AuthenticationExecutionRequirement requirement, AuthenticationExecutionRequirement currentRequirement) {
        for (AuthenticationFlowModel flow : realm.getAuthenticationFlows()) {
            for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutions(flow.getId())) {
                String providerId = execution.getAuthenticator();
                ConfigurableAuthenticatorFactory factory = getConfigurableAuthenticatorFactory(session, providerId);
                if (factory == null) continue;
                if (type.equals(factory.getReferenceCategory())) {
                    if (currentRequirement == null || currentRequirement.equals(execution.getRequirement())) {
                        execution.setRequirement(requirement);
                        realm.updateAuthenticatorExecution(execution);
                        LOG.debug("Authenticator execution '{}' switched to '{}'", execution.getAuthenticator(), requirement.toString());
                    } else {
                        LOG.debug("Skip switch authenticator execution '{}' to '{}' as it's in state {}", execution.getAuthenticator(), requirement.toString(), execution.getRequirement());
                    }
                }
            }
        }
    }

    public static ConfigurableAuthenticatorFactory getConfigurableAuthenticatorFactory(KeycloakSession session, String providerId) {
        ConfigurableAuthenticatorFactory factory = (AuthenticatorFactory) session.getSessionFactory().getProviderFactory(Authenticator.class, providerId);
        if (factory == null) {
            factory = (FormActionFactory) session.getSessionFactory().getProviderFactory(FormAction.class, providerId);
        }
        if (factory == null) {
            factory = (ClientAuthenticatorFactory) session.getSessionFactory().getProviderFactory(ClientAuthenticator.class, providerId);
        }
        return factory;
    }

    /**
     * Create OTP credential either in userStorage or local storage (Keycloak DB)
     *
     * @return true if credential was successfully created either in the user storage or Keycloak DB. False if error happened (EG. during HOTP validation)
     */
    public static boolean createOTPCredential(KeycloakSession session, RealmModel realm, UserModel user, String totpCode, OTPCredentialModel credentialModel) {
        CredentialProvider otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
        String totpSecret = credentialModel.getOTPSecretData().getValue();

        UserCredentialModel otpUserCredential = new UserCredentialModel("", realm.getOTPPolicy().getType(), totpSecret);
        boolean userStorageCreated = session.userCredentialManager().updateCredential(realm, user, otpUserCredential);

        String credentialId = null;
        if (userStorageCreated) {
            LOG.debug("Created OTP credential for user '{}' in the user storage", user.getUsername());
        } else {
            CredentialModel createdCredential = otpCredentialProvider.createCredential(realm, user, credentialModel);
            credentialId = createdCredential.getId();
        }

        //If the type is HOTP, call verify once to consume the OTP used for registration and increase the counter.
        UserCredentialModel credential = new UserCredentialModel(credentialId, otpCredentialProvider.getType(), totpCode);
        return session.userCredentialManager().isValid(realm, user, credential);
    }

    public static void deleteOTPCredential(KeycloakSession session, RealmModel realm, UserModel user, String credentialId) {
        CredentialProvider otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
        boolean removed = otpCredentialProvider.deleteCredential(realm, user, credentialId);

        // This can usually happened when credential is stored in the userStorage. Propagate to "disable" credential in the userStorage
        if (!removed) {
            LOG.debug("Removing OTP credential from userStorage");
            session.userCredentialManager().disableCredentialType(realm, user, OTPCredentialModel.TYPE);
        }
    }

    /**
     * Create "dummy" representation of the credential. Typically used when credential is provided by userStorage and we don't know further
     * details about the credential besides the type
     *
     * @param credentialProviderType
     * @return dummy credential
     */
    public static CredentialRepresentation createUserStorageCredentialRepresentation(String credentialProviderType) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setId(credentialProviderType + "-id");
        credential.setType(credentialProviderType);
        credential.setCreatedDate(-1L);
        credential.setPriority(0);
        return credential;
    }
}
