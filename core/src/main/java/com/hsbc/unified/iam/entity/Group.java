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
@Table(name = "KEYCLOAK_GROUP",
        uniqueConstraints = {@UniqueConstraint(columnNames = {"REALM_ID", "PARENT_GROUP", "NAME"})}
)
public class Group {

    /**
     * ID set in the PARENT column to mark the group as top level.
     */
    public static String TOP_PARENT_ID = " ";

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Nationalized
    @Column(name = "NAME")
    protected String name;
    @OneToMany(
            cascade = CascadeType.REMOVE,
            orphanRemoval = true, mappedBy = "group")
    protected Collection<GroupAttribute> attributes = new ArrayList<GroupAttribute>();
    @Column(name = "PARENT_GROUP")
    private String parentId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    private Realm realm;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Collection<GroupAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(Collection<GroupAttribute> attributes) {
        this.attributes = attributes;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(String parentId) {
        this.parentId = parentId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof Group)) return false;

        Group that = (Group) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
