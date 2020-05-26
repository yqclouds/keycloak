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
 * User Form.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class UserForm implements Serializable {
    @NotEmpty
    @Length(max = 64)
    private String username;

    private Long[] groups;

    private Long[] roles;

    private boolean existed;

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public Long[] getGroups() {
        return groups;
    }

    public void setGroups(final Long[] groups) {
        this.groups = groups;
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
