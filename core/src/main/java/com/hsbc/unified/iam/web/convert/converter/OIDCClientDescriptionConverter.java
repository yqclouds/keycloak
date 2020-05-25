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

package com.hsbc.unified.iam.web.convert.converter;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientregistration.oidc.DescriptionConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.io.IOException;

@Component("OIDCClientDescriptionConverter")
public class OIDCClientDescriptionConverter implements ClientDescriptionConverter {
    @Autowired
    private DescriptionConverter descriptionConverter;

    @Override
    public boolean supports(String description) {
        description = description.trim();
        return (description.startsWith("{") && description.endsWith("}") && description.contains("\"redirect_uris\""));
    }

    @Override
    public ClientRepresentation convert(@NotNull String content) {
        try {
            OIDCClientRepresentation clientOIDC = JsonSerialization.readValue(content, OIDCClientRepresentation.class);
            return descriptionConverter.toInternal(clientOIDC);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
