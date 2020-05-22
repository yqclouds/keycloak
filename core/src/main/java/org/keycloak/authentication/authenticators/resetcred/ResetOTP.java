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

package org.keycloak.authentication.authenticators.resetcred;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("ResetOTP")
@ProviderFactory(id = "reset-otp", providerClasses = Authenticator.class)
public class ResetOTP extends AbstractSetRequiredActionAuthenticator implements CredentialValidator<OTPCredentialProvider> {

    public static final String PROVIDER_ID = "reset-otp";
    @Autowired
    private UserCredentialManager userCredentialManager;
    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    @Override
    public String getType() {
        return getCredentialProvider().getType();
    }

    @Override
    public List<CredentialModel> getCredentials(RealmModel realm, UserModel user) {
        return userCredentialManager.getStoredCredentialsByType(realm, user, getCredentialProvider().getType());
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        context.success();
    }

    @Override
    public OTPCredentialProvider getCredentialProvider() {
        return (OTPCredentialProvider) credentialProviders.get("keycloak-otp");
    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        return getCredentialProvider().isConfiguredFor(realm, user);
    }

    @Override
    public String getDisplayType() {
        return "Reset OTP";
    }

    @Override
    public String getHelpText() {
        return "Sets the Configure OTP required action.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
