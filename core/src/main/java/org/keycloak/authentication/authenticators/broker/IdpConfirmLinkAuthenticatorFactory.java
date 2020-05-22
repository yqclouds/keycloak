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

package org.keycloak.authentication.authenticators.broker;

import com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("IdpConfirmLinkAuthenticatorFactory")
@ProviderFactory(id = "idp-confirm-link", providerClasses = IdpConfirmLinkAuthenticator.class)
public class IdpConfirmLinkAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-confirm-link";
    static IdpConfirmLinkAuthenticator SINGLETON = new IdpConfirmLinkAuthenticator();

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
        return "confirmLink";
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
        return "Confirm link existing account";
    }

    @Override
    public String getHelpText() {
        return "Show the form where user confirms if he wants to link identity provider with existing account or rather edit user profile data retrieved from identity provider to avoid conflict";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


}
