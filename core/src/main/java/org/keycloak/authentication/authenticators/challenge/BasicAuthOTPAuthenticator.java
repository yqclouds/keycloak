/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authentication.authenticators.challenge;

import com.hsbc.unified.iam.facade.model.credential.OTPCredentialModel;
import com.hsbc.unified.iam.facade.model.credential.UserCredentialModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class BasicAuthOTPAuthenticator extends BasicAuthAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {
    @Autowired
    private UserCredentialManager userCredentialManager;

    public List<CredentialModel> getCredentials(RealmModel realm, UserModel user) {
        return userCredentialManager.getStoredCredentialsByType(realm, user, getCredentialProvider().getType());
    }

    public String getType() {
        return getCredentialProvider().getType();
    }

    @Override
    protected boolean onAuthenticate(AuthenticationFlowContext context, String[] challenge) {
        String username = challenge[0];
        String password = challenge[1];
        OTPPolicy otpPolicy = context.getRealm().getOTPPolicy();
        int otpLength = otpPolicy.getDigits();

        if (password.length() < otpLength) {
            return false;
        }

        password = password.substring(0, password.length() - otpLength);

        if (checkUsernameAndPassword(context, username, password)) {
            String otp = challenge[1].substring(password.length(), challenge[1].length());

            if (checkOtp(context, otp)) {
                return true;
            }
        }

        return false;
    }

    private boolean checkOtp(AuthenticationFlowContext context, String otp) {
        OTPCredentialModel preferredCredential = getCredentialProvider()
                .getDefaultCredential(userCredentialManager, context.getRealm(), context.getUser());
        boolean valid = getCredentialProvider().isValid(context.getRealm(), context.getUser(),
                new UserCredentialModel(preferredCredential.getId(), getCredentialProvider().getType(), otp));

        if (!valid) {
            context.getEvent().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
            if (context.getExecution().isRequired()) {
                Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            } else {
                context.attempted();
            }
            return false;
        }

        return true;
    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        return getCredentialProvider().isConfiguredFor(realm, user);
    }

    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    @Override
    public OTPCredentialProvider getCredentialProvider() {
        return (OTPCredentialProvider) credentialProviders.get("keycloak-otp");
    }
}

