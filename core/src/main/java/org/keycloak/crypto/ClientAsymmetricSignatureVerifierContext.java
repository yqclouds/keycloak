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
package org.keycloak.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.ClientModel;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

public class ClientAsymmetricSignatureVerifierContext extends AsymmetricSignatureVerifierContext {
    private final ClientModel client;
    private final JWSInput input;

    @Autowired
    private PublicKeyStorageManager publicKeyStorageManager;

    public ClientAsymmetricSignatureVerifierContext(ClientModel client, JWSInput input) {
        super();

        this.client = client;
        this.input = input;
    }

    @PostConstruct
    public void afterPropertiesSet() throws VerificationException {
        setKey(getKey(client, input));
    }

    private KeyWrapper getKey(ClientModel client, JWSInput input) throws VerificationException {
        KeyWrapper key = publicKeyStorageManager.getClientPublicKeyWrapper(client, input);
        if (key == null) {
            throw new VerificationException("Key not found");
        }
        return key;
    }
}
