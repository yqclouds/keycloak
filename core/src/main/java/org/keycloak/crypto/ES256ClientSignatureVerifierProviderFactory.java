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

import com.hsbc.unified.iam.core.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

@Component("ES256ClientSignatureVerifierProviderFactory")
@ProviderFactory(id = Algorithm.ES256, providerClasses = ClientSignatureVerifierProvider.class)
public class ES256ClientSignatureVerifierProviderFactory implements ClientSignatureVerifierProviderFactory {

    public static final String ID = Algorithm.ES256;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public ClientSignatureVerifierProvider create(KeycloakSession session) {
        return new ECDSAClientSignatureVerifierProvider(session, Algorithm.ES256);
    }

}