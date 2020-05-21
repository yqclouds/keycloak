/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

@Component("Aes128GcmContentEncryptionProviderFactory")
@ProviderFactory(id = JWEConstants.A128GCM, providerClasses = ContentEncryptionProvider.class)
public class Aes128GcmContentEncryptionProviderFactory implements ContentEncryptionProviderFactory {
    public static final String ID = JWEConstants.A128GCM;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public ContentEncryptionProvider create() {
        return new AesGcmContentEncryptionProvider(JWEConstants.A128GCM);
    }

}
