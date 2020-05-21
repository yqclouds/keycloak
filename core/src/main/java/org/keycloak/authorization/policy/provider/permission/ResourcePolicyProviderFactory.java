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
package org.keycloak.authorization.policy.provider.permission;

import org.keycloak.authorization.AuthorizationProvider;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component("ResourcePolicyProviderFactory")
@ProviderFactory(id = "resource", providerClasses = PolicyProvider.class)
public class ResourcePolicyProviderFactory implements PolicyProviderFactory<ResourcePermissionRepresentation> {

    private ResourcePolicyProvider provider = new ResourcePolicyProvider();

    @Override
    public String getName() {
        return "ResourceModel-Based";
    }

    @Override
    public String getGroup() {
        return "Permission";
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return provider;
    }

    @Override
    public Class<ResourcePermissionRepresentation> getRepresentationType() {
        return ResourcePermissionRepresentation.class;
    }

    @Override
    public ResourcePermissionRepresentation toRepresentation(PolicyModel policy, AuthorizationProvider authorization) {
        ResourcePermissionRepresentation representation = new ResourcePermissionRepresentation();
        representation.setResourceType(policy.getConfig().get("defaultResourceType"));
        return representation;
    }

    @Override
    public PolicyProvider create() {
        return null;
    }

    @Override
    public void onCreate(PolicyModel policy, ResourcePermissionRepresentation representation, AuthorizationProvider authorization) {
        updateResourceType(policy, representation);
    }

    @Override
    public void onUpdate(PolicyModel policy, ResourcePermissionRepresentation representation, AuthorizationProvider authorization) {
        updateResourceType(policy, representation);
    }

    private void updateResourceType(PolicyModel policy, ResourcePermissionRepresentation representation) {
        if (representation != null) {
            //TODO: remove this check once we migrate to new API
            if (ResourcePermissionRepresentation.class.equals(representation.getClass())) {
                ResourcePermissionRepresentation resourcePermission = ResourcePermissionRepresentation.class.cast(representation);
                Map<String, String> config = new HashMap(policy.getConfig());

                config.compute("defaultResourceType", (key, value) -> {
                    String resourceType = resourcePermission.getResourceType();
                    return resourceType != null ? resourcePermission.getResourceType() : null;
                });

                policy.setConfig(config);

            }
        }
    }

    @Override
    public void onRemove(PolicyModel policy, AuthorizationProvider authorization) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "resource";
    }
}
