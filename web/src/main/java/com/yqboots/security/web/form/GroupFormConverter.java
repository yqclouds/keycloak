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

import com.yqboots.security.core.Group;
import com.yqboots.security.core.Role;
import com.yqboots.security.core.User;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.core.convert.converter.Converter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Convert {@link Group} to {@link GroupForm}, for web form use.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class GroupFormConverter implements Converter<Group, GroupForm> {
    /**
     * {@inheritDoc}
     */
    @Override
    public GroupForm convert(final Group source) {
        GroupForm result = new GroupForm();
        result.setPath(source.getPath());
        result.setAlias(source.getAlias());
        result.setDescription(source.getDescription());
        result.setExisted(!source.isNew());
        result.setUsers(getUsers(source.getUsers()));
        result.setRoles(getRoles(source.getRoles()));

        return result;
    }

    /**
     * Gets the id of users.
     *
     * @param users users
     * @return id of users
     */
    private Long[] getUsers(Set<User> users) {
        List<Long> results = new ArrayList<>();
        if (CollectionUtils.isNotEmpty(users)) {
            results.addAll(users.stream().map(User::getId).collect(Collectors.toList()));
        }

        return results.toArray(new Long[results.size()]);
    }

    /**
     * Gets the id of roles.
     *
     * @param roles roles
     * @return id of roles
     */
    private Long[] getRoles(Set<Role> roles) {
        List<Long> results = new ArrayList<>();
        if (CollectionUtils.isNotEmpty(roles)) {
            results.addAll(roles.stream().map(Role::getId).collect(Collectors.toList()));
        }

        return results.toArray(new Long[results.size()]);
    }
}
