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
package org.keycloak.adapters.authorization.cip;

import org.keycloak.adapters.authorization.ClaimInformationPointProviderFactory;
import org.keycloak.adapters.authorization.PolicyEnforcer;

import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClaimsInformationPointProviderFactory implements ClaimInformationPointProviderFactory<ClaimsInformationPointProvider> {

    @Override
    public String getName() {
        return "claims";
    }

    @Override
    public void init(PolicyEnforcer policyEnforcer) {

    }

    @Override
    public ClaimsInformationPointProvider create(Map<String, Object> config) {
        return new ClaimsInformationPointProvider(config);
    }
}
