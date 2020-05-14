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

import com.hsbc.unified.iam.core.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import com.hsbc.unified.iam.facade.model.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("BasicAuthOTPAuthenticatorFactory")
@ProviderFactory(id = "basic-auth-otp", providerClasses = Authenticator.class)
public class BasicAuthOTPAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "basic-auth-otp";
    public static final BasicAuthOTPAuthenticator SINGLETON = new BasicAuthOTPAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionRequirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Basic Auth Password+OTP";
    }

    @Override
    public String getHelpText() {
        return "Challenge-response authentication using HTTP BASIC scheme.  Password param should contain a combination of password + otp. Realm's OTP policy is used to determine how to parse this. This SHOULD NOT BE USED in conjection with regular basic auth provider.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    @Deprecated
    public String getId() {
        return PROVIDER_ID;
    }
}

