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

import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

public class ServerAsymmetricSignatureSignerContext extends AsymmetricSignatureSignerContext {
    @Autowired
    private KeycloakContext context;
    @Autowired
    private KeyManager keyManager;

    private String algorithm;

    public ServerAsymmetricSignatureSignerContext(String algorithm) throws SignatureException {
        super(null);
        this.algorithm = algorithm;
    }

    @PostConstruct
    public void afterPropertiesSet() {
        setKey(getKey(algorithm));
    }

    public KeyWrapper getKey(String algorithm) {
        KeyWrapper key = keyManager.getActiveKey(context.getRealm(), KeyUse.SIG, algorithm);
        if (key == null) {
            throw new SignatureException("Active key for " + algorithm + " not found");
        }
        return key;
    }

}
