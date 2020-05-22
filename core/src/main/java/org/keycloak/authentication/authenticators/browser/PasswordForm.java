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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Map;

public class PasswordForm extends UsernamePasswordForm implements CredentialValidator<PasswordCredentialProvider> {
    @Autowired
    private UserCredentialManager userCredentialManager;
    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    @Override
    public List<CredentialModel> getCredentials(RealmModel realm, UserModel user) {
        return userCredentialManager.getStoredCredentialsByType(realm, user, getCredentialProvider().getType());
    }

    @Override
    public String getType() {
        return getCredentialProvider().getType();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validatePassword(context, context.getUser(), formData, false);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = context.form().createLoginPassword();
        context.challenge(challengeResponse);
    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        // never called
        return getCredentialProvider().isConfiguredFor(realm, user, getType());
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginPassword();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return Messages.INVALID_PASSWORD;
    }

    @Override
    public PasswordCredentialProvider getCredentialProvider() {
        return (PasswordCredentialProvider) credentialProviders.get("keycloak-password");
    }
}
