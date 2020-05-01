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

package org.keycloak.models.sessions.infinispan;

import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.StickySessionEncoderProvider;
import org.keycloak.sessions.StickySessionEncoderProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@ProviderFactory(id = "infinispan")
public class InfinispanStickySessionEncoderProviderFactory implements StickySessionEncoderProviderFactory {
    @Value("${shouldAttachRoute}")
    private boolean shouldAttachRoute;

    @Override
    public StickySessionEncoderProvider create(KeycloakSession session) {
        return new InfinispanStickySessionEncoderProvider(session, shouldAttachRoute);
    }

    // Used for testing
    public void setShouldAttachRoute(boolean shouldAttachRoute) {
        this.shouldAttachRoute = shouldAttachRoute;
    }

    @Override
    public String getId() {
        return "infinispan";
    }
}
