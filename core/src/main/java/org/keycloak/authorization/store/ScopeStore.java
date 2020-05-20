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
package org.keycloak.authorization.store;


import org.keycloak.authorization.model.ResourceServerModel;
import org.keycloak.authorization.model.ScopeModel;

import java.util.List;
import java.util.Map;

/**
 * A {@link ScopeStore} is responsible to manage the persistence of {@link ScopeModel} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface ScopeStore {

    /**
     * Creates a new {@link ScopeModel} instance. The new instance is not necessarily persisted though, which may require
     * a call to the {#save} method to actually make it persistent.
     *
     * @param name           the name of the scope
     * @param resourceServer the resource server to which this scope belongs
     * @return a new instance of {@link ScopeModel}
     */
    ScopeModel create(String name, ResourceServerModel resourceServer);

    /**
     * Creates a new {@link ScopeModel} instance. The new instance is not necessarily persisted though, which may require
     * a call to the {#save} method to actually make it persistent.
     *
     * @param id             the id of the scope
     * @param name           the name of the scope
     * @param resourceServer the resource server to which this scope belongs
     * @return a new instance of {@link ScopeModel}
     */
    ScopeModel create(String id, String name, ResourceServerModel resourceServer);

    /**
     * Deletes a scope from the underlying persistence mechanism.
     *
     * @param id the id of the scope to delete
     */
    void delete(String id);

    /**
     * Returns a {@link ScopeModel} with the given <code>id</code>
     *
     * @param id               the identifier of the scope
     * @param resourceServerId the resource server id
     * @return a scope with the given identifier.
     */
    ScopeModel findById(String id, String resourceServerId);

    /**
     * Returns a {@link ScopeModel} with the given <code>name</code>
     *
     * @param name             the name of the scope
     * @param resourceServerId the resource server id
     * @return a scope with the given name.
     */
    ScopeModel findByName(String name, String resourceServerId);

    /**
     * Returns a list of {@link ScopeModel} associated with a {@link ResourceServerModel} with the given <code>resourceServerId</code>.
     *
     * @param resourceServerId the identifier of a resource server
     * @return a list of scopes that belong to the given resource server
     */
    List<ScopeModel> findByResourceServer(String id);

    /**
     * Returns a list of {@link ScopeModel} associated with a {@link ResourceServerModel} with the given <code>resourceServerId</code>.
     *
     * @param attributes       a map holding the attributes that will be used as a filter
     * @param resourceServerId the identifier of a resource server
     * @return a list of scopes that belong to the given resource server
     */
    List<ScopeModel> findByResourceServer(Map<String, String[]> attributes, String resourceServerId, int firstResult, int maxResult);
}