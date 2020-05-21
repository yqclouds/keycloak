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

package org.keycloak.forms.login.freemarker.model;

import com.hsbc.unified.iam.facade.model.credential.OTPCredentialModel;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Used for TOTP login
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TotpLoginBean {

    private final String selectedCredentialId;
    private final List<OTPCredential> userOtpCredentials;

    @Autowired
    private UserCredentialManager userCredentialManager;
    @Autowired
    private Map<String, CredentialProvider> credentialProviders;

    public TotpLoginBean(RealmModel realm, UserModel user, String selectedCredentialId) {
        List<CredentialModel> userOtpCredentials = userCredentialManager
                .getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE);

        this.userOtpCredentials = userOtpCredentials.stream()
                .map(OTPCredential::new)
                .collect(Collectors.toList());

        // This means user did not yet manually selected any OTP credential through the UI. So just go with the default one with biggest priority
        if (selectedCredentialId == null || selectedCredentialId.isEmpty()) {
            OTPCredentialProvider otpCredentialProvider = (OTPCredentialProvider) credentialProviders.get(OTPCredentialProviderFactory.PROVIDER_ID);
            OTPCredentialModel otpCredential = otpCredentialProvider
                    .getDefaultCredential(userCredentialManager, realm, user);

            selectedCredentialId = otpCredential == null ? null : otpCredential.getId();
        }

        this.selectedCredentialId = selectedCredentialId;
    }


    public List<OTPCredential> getUserOtpCredentials() {
        return userOtpCredentials;
    }

    public String getSelectedCredentialId() {
        return selectedCredentialId;
    }


    public static class OTPCredential {

        private final String id;
        private final String userLabel;

        public OTPCredential(CredentialModel credentialModel) {
            this.id = credentialModel.getId();
            // TODO: "Unnamed" OTP credentials should be displayed in the UI in gray
            this.userLabel = credentialModel.getUserLabel() == null || credentialModel.getUserLabel().isEmpty() ? OTPFormAuthenticator.UNNAMED : credentialModel.getUserLabel();
        }

        public String getId() {
            return id;
        }

        public String getUserLabel() {
            return userLabel;
        }
    }
}
