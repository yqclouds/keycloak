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

package org.keycloak.authorization.store.syncronization;

import com.hsbc.unified.iam.entity.events.RealmRemovedEvent;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.RealmModel;
import org.springframework.beans.factory.annotation.Autowired;

/*
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RealmSynchronizer implements Synchronizer<RealmRemovedEvent> {
    @Autowired
    private AuthorizationProvider authorizationProvider;

    @Override
    public void synchronize(RealmRemovedEvent event) {
        StoreFactory storeFactory = authorizationProvider.getStoreFactory();
        ((RealmModel) event.getSource()).getClients().forEach(clientModel -> {
            ResourceServerModel resourceServer = storeFactory.getResourceServerStore().findById(clientModel.getId());

            if (resourceServer != null) {
                String id = resourceServer.getId();
                storeFactory.getResourceServerStore().delete(id);
            }
        });
    }
}
