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
package com.hsbc.unified.iam.core.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

public class ServerAsymmetricSignatureVerifierContext extends AsymmetricSignatureVerifierContext {
    private final String kid;
    private final String algorithm;

    @Autowired
    private KeyManager keyManager;
    @Autowired
    private KeycloakContext context;

    public ServerAsymmetricSignatureVerifierContext(String kid, String algorithm) throws VerificationException {
        super();
        this.kid = kid;
        this.algorithm = algorithm;
    }

    @PostConstruct
    public void afterPropertiesSet() throws VerificationException {
        setKey(getKey(kid, algorithm));
    }

    KeyWrapper getKey(String kid, String algorithm) throws VerificationException {
        KeyWrapper key = keyManager.getKey(context.getRealm(), kid, KeyUse.SIG, algorithm);
        if (key == null) {
            throw new VerificationException("Key not found");
        }
        return key;
    }

}
