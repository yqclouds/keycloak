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

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * Group manager.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface GroupManager {
    /**
     * Adds new group.
     *
     * @param group group
     * @throws GroupExistsException throw when the entity exists
     */
    void addGroup(Group group) throws GroupExistsException;

    /**
     * Updates the group.
     *
     * @param group group
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void updateGroup(Group group) throws GroupNotFoundException;

    /**
     * Updates {@link User}s of the {@link Group}.
     *
     * @param path    path
     * @param userIds id of users
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void updateUsers(String path, Long... userIds) throws GroupNotFoundException;

    /**
     * Updates {@link User}s of the {@link Group}.
     *
     * @param path      path
     * @param usernames usernames
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void updateUsers(String path, String... usernames) throws GroupNotFoundException;

    /**
     * Updates {@link Role}s of the {@link Group}.
     *
     * @param path    path
     * @param roleIds id of roles
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void updateRoles(String path, Long... roleIds) throws GroupNotFoundException;

    /**
     * Updates {@link Role}s of the {@link Group}.
     *
     * @param path      path
     * @param rolePaths usernames
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void updateRoles(String path, String... rolePaths) throws GroupNotFoundException;

    /**
     * Removes the group.
     *
     * @param id identity of the group
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeGroup(Long id) throws GroupNotFoundException;

    /**
     * Removes the group.
     *
     * @param path path
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeGroup(String path) throws GroupNotFoundException;

    /**
     * Removes the {@link User}s from the {@link Group}.
     *
     * @param path    path
     * @param userIds id of users
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeUsers(String path, Long... userIds) throws GroupNotFoundException;

    /**
     * Removes the {@link User}s from the {@link Group}.
     *
     * @param path      path
     * @param usernames username of users
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeUsers(String path, String... usernames) throws GroupNotFoundException;

    /**
     * Removes the {@link Role}s from the {@link Group}.
     *
     * @param path    path
     * @param roleIds id of roles
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeRoles(String path, Long... roleIds) throws GroupNotFoundException;

    /**
     * Removes the {@link Role}s from the {@link Group}.
     *
     * @param path      path
     * @param rolePaths path of roles
     * @throws GroupNotFoundException throw when the entity is not found
     */
    void removeRoles(String path, String... rolePaths) throws GroupNotFoundException;

    /**
     * Checks if the {@link Group} exists.
     *
     * @param path path
     * @return true when the group with the specified path exists
     */
    boolean hasGroup(String path);

    /**
     * Finds {@link Group} by path.
     *
     * @param id identity of the group
     * @return the group
     * @throws GroupNotFoundException throw when the entity is not found
     */
    Group findGroup(Long id) throws GroupNotFoundException;

    /**
     * Finds {@link Group} by path.
     *
     * @param path path
     * @return the group
     * @throws GroupNotFoundException throw when the entity is not found
     */
    Group findGroup(String path) throws GroupNotFoundException;

    /**
     * Finds {@link Group}s by wildcard condition.
     *
     * @param pathFilter pathFilter
     * @param pageable   pageable
     * @return page of groups
     */
    Page<Group> findGroups(String pathFilter, Pageable pageable);

    /**
     * Finds {@link Group}s.
     *
     * @param pageable pageable
     * @return page of groups
     */
    Page<Group> findGroups(Pageable pageable);

    /**
     * @return list of groups
     */
    List<Group> findAllGroups();

    /**
     * Finds all {@link User}s which belong to the {@link Group}.
     *
     * @param path path
     * @return list of users
     */
    List<User> findGroupUsers(String path);

    /**
     * Finds all {@link Role}s which belong to the {@link Group}.
     *
     * @param path path
     * @return list of roles
     */
    List<Role> findGroupRoles(String path);
}
