/*
 *
 *  * Copyright 2015-2016 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.yqboots.security.core;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.hibernate.annotations.NaturalId;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.data.jpa.domain.AbstractPersistable;

import javax.persistence.*;
import java.util.Set;

/**
 * Group entity.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Entity
@Table(name = "SEC_GROUP", uniqueConstraints = {@UniqueConstraint(name = "UN_GROUP_PATH", columnNames = {"PATH"})})
public class Group extends AbstractPersistable<Long> {
    @NotEmpty
    @Length(max = 254)
    @Column(unique = true, length = 254, nullable = false)
    @NaturalId
    private String path;

    @NotEmpty
    @Length(max = 64)
    @Column(length = 64)
    private String alias;

    @Length(max = 254)
    @Column(length = 254)
    private String description;

    @ManyToMany(targetEntity = Role.class)
    @JoinTable(name = "SEC_GROUP_ROLES", joinColumns = @JoinColumn(name = "GROUP_ID"), inverseJoinColumns = @JoinColumn(name = "ROLE_ID"))
    private Set<Role> roles;

    @ManyToMany(mappedBy = "groups", cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    private Set<User> users;

    public Group() {
        super();
    }

    public Group(String path) {
        super();
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("path", path)
                .append("alias", alias)
                .append("description", description)
                .append("roles", roles)
                .append("users", users)
                .toString();
    }
}
