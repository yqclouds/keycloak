/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.requiredactions;

import com.webauthn4j.anchor.KeyStoreTrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.hsbc.unified.iam.core.constants.OAuth2Constants;
import org.keycloak.authentication.DisplayTypeRequiredActionFactory;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.truststore.TruststoreProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component("WebAuthnRegisterFactory")
@ProviderFactory(id = "webauthn-register", providerClasses = RequiredActionProvider.class)
public class WebAuthnRegisterFactory implements RequiredActionFactory, DisplayTypeRequiredActionFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "webauthn-register";

    @Autowired(required = false)
    private TruststoreProvider truststoreProvider;

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        WebAuthnRegister webAuthnRegister = null;
        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            webAuthnRegister = createProvider(session, new NullCertPathTrustworthinessValidator());
        } else {
            KeyStoreTrustAnchorsProvider trustAnchorsProvider = new KeyStoreTrustAnchorsProvider();
            trustAnchorsProvider.setKeyStore(truststoreProvider.getTruststore());
            TrustAnchorsResolverImpl resolverImpl = new TrustAnchorsResolverImpl(trustAnchorsProvider);
            TrustAnchorCertPathTrustworthinessValidator trustValidator = new TrustAnchorCertPathTrustworthinessValidator(resolverImpl);
            webAuthnRegister = createProvider(session, trustValidator);
        }
        return webAuthnRegister;
    }

    protected WebAuthnRegister createProvider(KeycloakSession session, CertPathTrustworthinessValidator trustValidator) {
        return new WebAuthnRegister(session, trustValidator);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return create(session);
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        // TODO : write console typed provider?
        return null;
    }

    @Override
    public String getDisplayText() {
        return "Webauthn Register";
    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.WEB_AUTHN);
    }
}