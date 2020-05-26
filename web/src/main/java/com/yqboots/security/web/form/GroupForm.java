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
package com.yqboots.security.web.form;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;

import java.io.Serializable;

/**
 * Group Form.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class GroupForm implements Serializable {
    @NotEmpty
    @Length(max = 254)
    private String path;

    @Length(max = 64)
    private String alias;

    @Length(max = 254)
    private String description;

    private Long[] users;

    private Long[] roles;

    private boolean existed;

    public String getPath() {
        return path;
    }

    public void setPath(final String path) {
        this.path = path;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(final String alias) {
        this.alias = alias;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    public Long[] getUsers() {
        return users;
    }

    public void setUsers(final Long[] users) {
        this.users = users;
    }

    public Long[] getRoles() {
        return roles;
    }

    public void setRoles(final Long[] roles) {
        this.roles = roles;
    }

    public boolean isExisted() {
        return existed;
    }

    public void setExisted(final boolean existed) {
        this.existed = existed;
    }
}
