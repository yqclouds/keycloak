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

package com.hsbc.unified.iam.entity;

import org.hibernate.annotations.Nationalized;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Entity
@Table(name = "CLIENT_SCOPE", uniqueConstraints = {@UniqueConstraint(columnNames = {"REALM_ID", "NAME"})})
public class ClientScope {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;
    @OneToMany(cascade = {CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "clientScope")
    protected Collection<ClientScopeAttribute> attributes = new ArrayList<>();
    @OneToMany(cascade = {CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "clientScope")
    Collection<ProtocolMapper> protocolMappers = new ArrayList<ProtocolMapper>();
    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;
    @Column(name = "NAME")
    private String name;
    @Nationalized
    @Column(name = "DESCRIPTION")
    private String description;
    @Column(name = "PROTOCOL")
    private String protocol;

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public Collection<ProtocolMapper> getProtocolMappers() {
        return protocolMappers;
    }

    public void setProtocolMappers(Collection<ProtocolMapper> protocolMappers) {
        this.protocolMappers = protocolMappers;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Collection<ClientScopeAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(Collection<ClientScopeAttribute> attributes) {
        this.attributes = attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof ClientScope)) return false;

        ClientScope that = (ClientScope) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
