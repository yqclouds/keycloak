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

package org.keycloak.protocol.oidc;

import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("OIDCWellKnownProviderFactory")
@ProviderFactory(id = "openid-configuration", providerClasses = WellKnownProvider.class)
public class OIDCWellKnownProviderFactory implements WellKnownProviderFactory {

    public static final String PROVIDER_ID = "openid-configuration";

    @Override
    public WellKnownProvider create() {
        return new OIDCWellKnownProvider();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
