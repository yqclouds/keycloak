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

package org.keycloak.credential;

import com.hsbc.unified.iam.core.credential.CredentialInput;
import com.hsbc.unified.iam.core.util.Base64;
import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.facade.dto.WebAuthnCredentialData;
import com.hsbc.unified.iam.facade.model.credential.WebAuthnCredentialModel;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.exception.WebAuthnException;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Credential provider for WebAuthn 2-factor credential of the user
 */
public class WebAuthnCredentialProvider implements CredentialProvider<WebAuthnCredentialModel>, CredentialInputValidator {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnCredentialProvider.class);

    private CredentialPublicKeyConverter credentialPublicKeyConverter;
    private AttestationStatementConverter attestationStatementConverter;

    @Autowired
    private UserCredentialManager userCredentialManager;

    public WebAuthnCredentialProvider(ObjectConverter objectConverter) {
        if (credentialPublicKeyConverter == null)
            credentialPublicKeyConverter = new CredentialPublicKeyConverter(objectConverter);
        if (attestationStatementConverter == null)
            attestationStatementConverter = new AttestationStatementConverter(objectConverter);
    }

    private UserCredentialStore getCredentialStore() {
        return userCredentialManager;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, WebAuthnCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }

        return getCredentialStore().createCredential(realm, user, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        LOG.debug("Delete WebAuthn credential. username = {}, credentialId = {}", user.getUsername(), credentialId);
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public WebAuthnCredentialModel getCredentialFromModel(CredentialModel model) {
        return WebAuthnCredentialModel.createFromCredentialModel(model);
    }


    /**
     * Convert WebAuthn credential input to the model, which can be saved in the persistent storage (DB)
     *
     * @param input     should be typically WebAuthnCredentialModelInput
     * @param userLabel label for the credential
     */
    public WebAuthnCredentialModel getCredentialModelFromCredentialInput(CredentialInput input, String userLabel) {
        if (!supportsCredentialType(input.getType())) return null;

        WebAuthnCredentialModelInput webAuthnModel = (WebAuthnCredentialModelInput) input;

        String aaguid = webAuthnModel.getAttestedCredentialData().getAaguid().toString();
        String credentialId = Base64.encodeBytes(webAuthnModel.getAttestedCredentialData().getCredentialId());
        String credentialPublicKey = credentialPublicKeyConverter.convertToDatabaseColumn(webAuthnModel.getAttestedCredentialData().getCOSEKey());
        long counter = webAuthnModel.getCount();

        WebAuthnCredentialModel model = WebAuthnCredentialModel.create(getType(), userLabel, aaguid, credentialId, null, credentialPublicKey, counter);

        model.setId(webAuthnModel.getCredentialDBId());

        return model;
    }


    /**
     * Convert WebAuthnCredentialModel, which was usually retrieved from DB, to the CredentialInput, which contains data in the webauthn4j specific format
     */
    private WebAuthnCredentialModelInput getCredentialInputFromCredentialModel(CredentialModel credential) {
        WebAuthnCredentialModel webAuthnCredential = getCredentialFromModel(credential);

        WebAuthnCredentialData credData = webAuthnCredential.getWebAuthnCredentialData();

        WebAuthnCredentialModelInput auth = new WebAuthnCredentialModelInput(getType());

        byte[] credentialId = null;
        try {
            credentialId = Base64.decode(credData.getCredentialId());
        } catch (IOException ioe) {
            // NOP
        }

        AAGUID aaguid = new AAGUID(credData.getAaguid());

        COSEKey pubKey = credentialPublicKeyConverter.convertToEntityAttribute(credData.getCredentialPublicKey());

        AttestedCredentialData attrCredData = new AttestedCredentialData(aaguid, credentialId, pubKey);

        auth.setAttestedCredentialData(attrCredData);

        long count = credData.getCounter();
        auth.setCount(count);

        auth.setCredentialDBId(credential.getId());

        return auth;
    }


    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;
        return !userCredentialManager.getStoredCredentialsByType(realm, user, credentialType).isEmpty();
    }


    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!WebAuthnCredentialModelInput.class.isInstance(input)) return false;

        WebAuthnCredentialModelInput context = WebAuthnCredentialModelInput.class.cast(input);
        List<WebAuthnCredentialModelInput> auths = getWebAuthnCredentialModelList(realm, user);

        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(); // not special setting is needed for authentication's validation.
        AuthenticationData authenticationData = null;

        try {
            for (WebAuthnCredentialModelInput auth : auths) {

                byte[] credentialId = auth.getAttestedCredentialData().getCredentialId();
                if (Arrays.equals(credentialId, context.getAuthenticationRequest().getCredentialId())) {
                    Authenticator authenticator = new AuthenticatorImpl(
                            auth.getAttestedCredentialData(),
                            auth.getAttestationStatement(),
                            auth.getCount()
                    );

                    // parse
                    authenticationData = webAuthnManager.parse(context.getAuthenticationRequest());
                    // validate
                    AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                            context.getAuthenticationParameters().getServerProperty(),
                            authenticator,
                            context.getAuthenticationParameters().isUserVerificationRequired()
                    );
                    webAuthnManager.validate(authenticationData, authenticationParameters);


                    LOG.debug("response.getAuthenticatorData().getFlags() = {}", authenticationData.getAuthenticatorData().getFlags());

                    // update authenticator counter
                    long count = auth.getCount();
                    CredentialModel credModel = getCredentialStore().getStoredCredentialById(realm, user, auth.getCredentialDBId());
                    WebAuthnCredentialModel webAuthnCredModel = getCredentialFromModel(credModel);
                    webAuthnCredModel.updateCounter(count + 1);
                    getCredentialStore().updateCredential(realm, user, webAuthnCredModel);

                    LOG.debug("Successfully validated WebAuthn credential for user %s", user.getUsername());
                    dumpCredentialModel(webAuthnCredModel, auth);

                    return true;
                }
            }
        } catch (WebAuthnException wae) {
            wae.printStackTrace();
            throw (wae);
        }
        // no authenticator matched
        return false;
    }


    @Override
    public String getType() {
        return WebAuthnCredentialModel.TYPE_TWOFACTOR;
    }


    private List<WebAuthnCredentialModelInput> getWebAuthnCredentialModelList(RealmModel realm, UserModel user) {
        List<CredentialModel> credentialModels = userCredentialManager.getStoredCredentialsByType(realm, user, getType());

        return credentialModels.stream()
                .map(this::getCredentialInputFromCredentialModel)
                .collect(Collectors.toList());
    }

    public void dumpCredentialModel(WebAuthnCredentialModel credential, WebAuthnCredentialModelInput auth) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("  Persisted Credential Info::");
            LOG.debug(Objects.toString(credential));
            LOG.debug("  Context Credential Info::");
            LOG.debug(Objects.toString(auth));
        }
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("webauthn-display-name")
                .helpText("webauthn-help-text")
                .iconCssClass("kcAuthenticatorWebAuthnClass")
                .createAction(WebAuthnRegisterFactory.PROVIDER_ID)
                .removeable(true)
                .build();
    }
}
