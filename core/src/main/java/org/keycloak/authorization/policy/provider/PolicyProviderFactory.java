/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.policy.provider;

import org.keycloak.authorization.AuthorizationProvider;
import com.hsbc.unified.iam.facade.model.authorization.PolicyModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyProviderFactory<R extends AbstractPolicyRepresentation> extends ProviderFactory<PolicyProvider> {

    String getName();

    String getGroup();

    default boolean isInternal() {
        return false;
    }

    PolicyProvider create(AuthorizationProvider authorization);

    R toRepresentation(PolicyModel policy, AuthorizationProvider authorization);

    Class<R> getRepresentationType();

    default void onCreate(PolicyModel policy, R representation, AuthorizationProvider authorization) {

    }

    default void onUpdate(PolicyModel policy, R representation, AuthorizationProvider authorization) {

    }

    default void onRemove(PolicyModel policy, AuthorizationProvider authorization) {

    }

    default void onImport(PolicyModel policy, PolicyRepresentation representation, AuthorizationProvider authorization) {

    }

    default void onExport(PolicyModel policy, PolicyRepresentation representation, AuthorizationProvider authorizationProvider) {
    }

    default PolicyProviderAdminService getAdminResource(ResourceServerModel resourceServer, AuthorizationProvider authorization) {
        return null;
    }
}