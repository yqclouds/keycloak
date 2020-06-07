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
package org.keycloak.authorization.admin;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyTypeResourceService extends PolicyResourceService {

    public PolicyTypeResourceService(PolicyModel policy, ResourceServerModel resourceServer, AuthorizationProvider authorization, AdminPermissionEvaluator auth) {
        super(policy, resourceServer, authorization, auth);
    }

    @Override
    protected AbstractPolicyRepresentation doCreateRepresentation(String payload) {
        String type = getPolicy().getType();
        Class<? extends AbstractPolicyRepresentation> representationType = authorization.getProviderFactory(type).getRepresentationType();

        if (representationType == null) {
            throw new RuntimeException("PolicyModel provider for type [" + type + "] returned a null representation type.");
        }

        AbstractPolicyRepresentation representation;

        try {
            representation = JsonSerialization.readValue(payload, representationType);
        } catch (IOException e) {
            throw new RuntimeException("Failed to deserialize JSON using policy provider for type [" + type + "].", e);
        }

        representation.setType(type);

        return representation;
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    protected AbstractPolicyRepresentation toRepresentation(PolicyModel policy, String fields, AuthorizationProvider authorization) {
        return modelToRepresentation.toRepresentation(policy, authorization, false, false, fields != null && fields.equals("*"));
    }
}
