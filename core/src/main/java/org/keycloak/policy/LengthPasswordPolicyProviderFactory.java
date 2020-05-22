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

package org.keycloak.policy;

import org.keycloak.models.KeycloakContext;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("LengthPasswordPolicyProviderFactory")
@ProviderFactory(id = "length", providerClasses = PasswordPolicyProvider.class)
public class LengthPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {

    public static final String ID = "length";

    @Override
    public String getId() {
        return ID;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public PasswordPolicyProvider create() {
        return new LengthPasswordPolicyProvider(keycloakContext);
    }

    @Override
    public String getDisplayName() {
        return "Minimum Length";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.INT_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return "8";
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }
}
