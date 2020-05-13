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

package com.hsbc.unified.iam.core.entity;

import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;
import org.hibernate.annotations.Nationalized;

import javax.persistence.*;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Entity
@Table(name = "KEYCLOAK_ROLE", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"NAME", "CLIENT_REALM_CONSTRAINT"})
})
public class Role {
    @OneToMany(cascade = CascadeType.REMOVE, orphanRemoval = true, mappedBy = "role")
    @Fetch(FetchMode.SELECT)
    @BatchSize(size = 20)
    protected List<RoleAttribute> attributes = new ArrayList<>();
    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;
    @Nationalized
    @Column(name = "NAME")
    private String name;
    @Nationalized
    @Column(name = "DESCRIPTION")
    private String description;
    // hax! couldn't get constraint to work properly
    @Column(name = "REALM_ID")
    private String realmId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM")
    private Realm realm;
    @Column(name = "CLIENT_ROLE")
    private boolean clientRole;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT")
    private Client client;
    // Hack to ensure that either name+client or name+realm are unique. Needed due to MS-SQL as it don't allow multiple NULL values in the column, which is part of constraint
    @Column(name = "CLIENT_REALM_CONSTRAINT", length = 36)
    private String clientRealmConstraint;
    @ManyToMany(fetch = FetchType.LAZY, cascade = {})
    @JoinTable(name = "COMPOSITE_ROLE", joinColumns = @JoinColumn(name = "COMPOSITE"), inverseJoinColumns = @JoinColumn(name = "CHILD_ROLE"))
    private Set<Role> compositeRoles = new HashSet<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public Collection<RoleAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<RoleAttribute> attributes) {
        this.attributes = attributes;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<Role> getCompositeRoles() {
        return compositeRoles;
    }

    public void setCompositeRoles(Set<Role> compositeRoles) {
        this.compositeRoles = compositeRoles;
    }

    public boolean isClientRole() {
        return clientRole;
    }

    public void setClientRole(boolean clientRole) {
        this.clientRole = clientRole;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
        this.clientRealmConstraint = realm.getId();
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
        if (client != null) {
            this.clientRealmConstraint = client.getId();
        }
    }

    public String getClientRealmConstraint() {
        return clientRealmConstraint;
    }

    public void setClientRealmConstraint(String clientRealmConstraint) {
        this.clientRealmConstraint = clientRealmConstraint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof Role)) return false;

        Role that = (Role) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
