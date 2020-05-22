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

package org.keycloak.exportimport;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("KeycloakClientDescriptionConverter")
@ProviderFactory(id = "keycloak", providerClasses = ClientDescriptionConverter.class)
public class KeycloakClientDescriptionConverter implements ClientDescriptionConverterFactory, ClientDescriptionConverter {

    public static final String ID = "keycloak";

    @Override
    public boolean isSupported(String description) {
        description = description.trim();
        return (description.startsWith("{") && description.endsWith("}") && description.contains("\"clientId\""));
    }

    @Override
    public ClientRepresentation convertToInternal(String description) {
        try {
            return JsonSerialization.readValue(description, ClientRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ClientDescriptionConverter create() {
        return this;
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

}
