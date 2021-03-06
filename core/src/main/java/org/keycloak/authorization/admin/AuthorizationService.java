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

package org.keycloak.authorization.admin;

import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.models.ClientModel;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import javax.ws.rs.Path;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationService {

    private final ClientModel client;

    @Autowired
    private AuthorizationProvider authorizationProvider;
    private ResourceServerModel resourceServer;

    public AuthorizationService(ClientModel client) {
        this.client = client;
    }

    @PostConstruct
    public void afterPropertiesSet() {
        this.resourceServer = this.authorizationProvider.getStoreFactory().getResourceServerStore().findById(this.client.getId());
    }

    @Path("/resource-server")
    public ResourceServerService resourceServer() {
        ResourceServerService resource = new ResourceServerService(
                this.authorizationProvider, this.resourceServer, this.client
        );

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    public void enable(boolean newClient) {
        this.resourceServer = resourceServer().create(newClient);
    }

    public void disable() {
        if (isEnabled()) {
            resourceServer().delete();
        }
    }

    public boolean isEnabled() {
        return this.resourceServer != null;
    }
}
