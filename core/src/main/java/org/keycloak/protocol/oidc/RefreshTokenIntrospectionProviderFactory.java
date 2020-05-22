/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.keycloak.protocol.oidc;

import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Component("RefreshTokenIntrospectionProviderFactory")
@ProviderFactory(id = "refresh_token", providerClasses = TokenIntrospectionProvider.class)
public class RefreshTokenIntrospectionProviderFactory extends AccessTokenIntrospectionProviderFactory {

    private static final String REFRESH_TOKEN_TYPE = "refresh_token";

    @Override
    public TokenIntrospectionProvider create() {
        return new RefreshTokenIntrospectionProvider();
    }

    @Override
    public String getId() {
        return REFRESH_TOKEN_TYPE;
    }
}
