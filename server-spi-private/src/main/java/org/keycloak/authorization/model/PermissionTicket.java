/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authorization.model;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PermissionTicket {

    String ID = "id";
    String RESOURCE = "resource.id";
    String RESOURCE_NAME = "resource.name";
    String SCOPE = "scope.id";
    String SCOPE_IS_NULL = "scope_is_null";
    String OWNER = "owner";
    String GRANTED = "granted";
    String REQUESTER = "requester";
    String REQUESTER_IS_NULL = "requester_is_null";
    String POLICY_IS_NOT_NULL = "policy_is_not_null";
    String POLICY = "policy";

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the resource's owner, which is usually an identifier that uniquely identifies the resource's owner.
     *
     * @return the owner of this resource
     */
    String getOwner();

    String getRequester();

    /**
     * Returns the {@link Resource} associated with this instance
     *
     * @return the {@link Resource} associated with this instance
     */
    Resource getResource();

    /**
     * Returns the {@link Scope} associated with this instance
     *
     * @return the {@link Scope} associated with this instance
     */
    Scope getScope();

    boolean isGranted();

    Long getCreatedTimestamp();

    Long getGrantedTimestamp();

    void setGrantedTimestamp(Long millis);

    /**
     * Returns the {@link ResourceServer} where this policy belongs to.
     *
     * @return a resource server
     */
    ResourceServer getResourceServer();

    Policy getPolicy();

    void setPolicy(Policy policy);
}
