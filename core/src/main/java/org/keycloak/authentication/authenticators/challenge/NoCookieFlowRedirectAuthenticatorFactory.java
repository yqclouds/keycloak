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

import com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("NoCookieFlowRedirectAuthenticatorFactory")
@ProviderFactory(id = "no-cookie-redirect", providerClasses = Authenticator.class)
public class NoCookieFlowRedirectAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "no-cookie-redirect";
    public static final NoCookieFlowRedirectAuthenticator SINGLETON = new NoCookieFlowRedirectAuthenticator();
    public static final AuthenticationExecutionRequirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionRequirement.REQUIRED
    };

    @Override
    public Authenticator create() {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
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
        return "Browser Redirect/Refresh";
    }

    @Override
    public String getHelpText() {
        return "Perform a 302 redirect to get user agent's current URI on authenticate path with an auth_session_id query parameter.  This is for client's that do not support cookies.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
