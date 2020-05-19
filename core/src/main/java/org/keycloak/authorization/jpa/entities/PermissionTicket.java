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

package org.keycloak.authorization.jpa.entities;

import javax.persistence.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
@Table(name = "RESOURCE_SERVER_PERM_TICKET", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"OWNER", "RESOURCE_SERVER_ID", "RESOURCE_ID", "SCOPE_ID"})
})
public class PermissionTicket {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @Column(name = "OWNER")
    private String owner;

    @Column(name = "REQUESTER")
    private String requester;

    @Column(name = "CREATED_TIMESTAMP")
    private Long createdTimestamp;

    @Column(name = "GRANTED_TIMESTAMP")
    private Long grantedTimestamp;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "RESOURCE_ID")
    private Resource resource;

    @ManyToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "SCOPE_ID")
    private ScopeEntity scope;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "RESOURCE_SERVER_ID")
    private ResourceServer resourceServer;

    @ManyToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "POLICY_ID")
    private Policy policy;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public Resource getResource() {
        return resource;
    }

    public void setResource(Resource resource) {
        this.resource = resource;
    }

    public ScopeEntity getScope() {
        return scope;
    }

    public void setScope(ScopeEntity scope) {
        this.scope = scope;
    }

    public ResourceServer getResourceServer() {
        return resourceServer;
    }

    public void setResourceServer(ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
    }

    public String getRequester() {
        return requester;
    }

    public void setRequester(String requester) {
        this.requester = requester;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(Long createdTimestamp) {
        this.createdTimestamp = createdTimestamp;
    }

    public Long getGrantedTimestamp() {
        return grantedTimestamp;
    }

    public void setGrantedTimestamp(long grantedTimestamp) {
        this.grantedTimestamp = grantedTimestamp;
    }

    public boolean isGranted() {
        return grantedTimestamp != null;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PermissionTicket that = (PermissionTicket) o;

        return getId().equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
