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

import org.keycloak.authorization.AuthorizationProvider;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionService extends PolicyService {

    public PermissionService(ResourceServerModel resourceServer, AuthorizationProvider authorization, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        super(resourceServer, authorization, auth, adminEvent);
    }

    @Override
    protected PolicyResourceService doCreatePolicyResource(PolicyModel policy) {
        return new PolicyTypeResourceService(policy, resourceServer, authorization, auth, adminEvent);
    }

    @Override
    protected PolicyTypeService doCreatePolicyTypeResource(String type) {
        return new PolicyTypeService(type, resourceServer, authorization, auth, adminEvent) {
            @Override
            protected List<Object> doSearch(Integer firstResult, Integer maxResult, String fields, Map<String, String[]> filters) {
                filters.put("permission", new String[]{Boolean.TRUE.toString()});
                filters.put("type", new String[]{type});
                return super.doSearch(firstResult, maxResult, fields, filters);
            }
        };
    }

    @Override
    protected List<Object> doSearch(Integer firstResult, Integer maxResult, String fields, Map<String, String[]> filters) {
        filters.put("permission", new String[]{Boolean.TRUE.toString()});
        return super.doSearch(firstResult, maxResult, fields, filters);
    }

    @Autowired
    private ModelToRepresentation modelToRepresentation;

    @Override
    protected AbstractPolicyRepresentation toRepresentation(PolicyModel policy, String fields, AuthorizationProvider authorization) {
        return modelToRepresentation.toRepresentation(policy, authorization, false, false, fields != null && fields.equals("*"));
    }
}
