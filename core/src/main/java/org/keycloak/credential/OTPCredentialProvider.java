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
package org.keycloak.credential;

import com.hsbc.unified.iam.core.credential.CredentialInput;
import org.keycloak.models.CredentialModel;
import org.keycloak.common.util.ObjectUtil;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.models.*;
import com.hsbc.unified.iam.facade.model.credential.OTPCredentialModel;
import com.hsbc.unified.iam.facade.dto.OTPCredentialData;
import com.hsbc.unified.iam.facade.dto.OTPSecretData;
import com.hsbc.unified.iam.facade.model.credential.UserCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OTPCredentialProvider implements CredentialProvider<OTPCredentialModel>, CredentialInputValidator/*, OnUserCache*/ {
    private static final Logger LOG = LoggerFactory.getLogger(OTPCredentialProvider.class);

    protected KeycloakSession session;

    /*protected List<CredentialModel> getCachedCredentials(UserModel user, String type) {
        if (!(user instanceof CachedUserModel)) return null;
        CachedUserModel cached = (CachedUserModel)user;
        if (cached.isMarkedForEviction()) return null;
        List<CredentialModel> rtn = (List<CredentialModel>)cached.getCachedWith().get(getType());
        if (rtn == null) return Collections.EMPTY_LIST;
        return rtn;
    }*/

    public OTPCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    /*@Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<CredentialModel> creds = getCredentialStore().getStoredCredentialsByType(realm, user, getType());
        user.getCachedWith().put(getType(), creds);

    }*/

    private UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, OTPCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return getCredentialStore().createCredential(realm, user, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public OTPCredentialModel getCredentialFromModel(CredentialModel model) {
        return OTPCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;
        return !getCredentialStore().getStoredCredentialsByType(realm, user, credentialType).isEmpty();
    }

    public boolean isConfiguredFor(RealmModel realm, UserModel user) {
        return isConfiguredFor(realm, user, getType());
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        if (!(credentialInput instanceof UserCredentialModel)) {
            LOG.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;

        }
        String challengeResponse = credentialInput.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }
        if (ObjectUtil.isBlank(credentialInput.getCredentialId())) {
            LOG.debug("CredentialId is null when validating credential of user %s", user.getUsername());
            return false;
        }

        CredentialModel credential = getCredentialStore().getStoredCredentialById(realm, user, credentialInput.getCredentialId());
        OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credential);
        OTPSecretData secretData = otpCredentialModel.getOTPSecretData();
        OTPCredentialData credentialData = otpCredentialModel.getOTPCredentialData();
        OTPPolicy policy = realm.getOTPPolicy();
        if (OTPCredentialModel.HOTP.equals(credentialData.getSubType())) {
            HmacOTP validator = new HmacOTP(credentialData.getDigits(), credentialData.getAlgorithm(), policy.getLookAheadWindow());
            int counter = validator.validateHOTP(challengeResponse, secretData.getValue(), credentialData.getCounter());
            if (counter < 0) {
                return false;
            }
            otpCredentialModel.updateCounter(counter);
            getCredentialStore().updateCredential(realm, user, otpCredentialModel);
            return true;
        } else if (OTPCredentialModel.TOTP.equals(credentialData.getSubType())) {
            TimeBasedOTP validator = new TimeBasedOTP(credentialData.getAlgorithm(), credentialData.getDigits(), credentialData.getPeriod(), policy.getLookAheadWindow());
            return validator.validateTOTP(challengeResponse, secretData.getValue().getBytes(StandardCharsets.UTF_8));
        }
        return false;
    }

    @Override
    public String getType() {
        return OTPCredentialModel.TYPE;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("otp-display-name")
                .helpText("otp-help-text")
                .iconCssClass("kcAuthenticatorOTPClass")
                .createAction(UserModel.RequiredAction.CONFIGURE_TOTP.toString())
                .removeable(true)
                .build(session);
    }
}
