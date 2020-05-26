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
 * Role manager.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface RoleManager {
    /**
     * Adds new role.
     *
     * @param role role
     * @throws RoleExistsException throw when the entity exists
     */
    void addRole(Role role) throws RoleExistsException;

    /**
     * Updates the role.
     *
     * @param role role
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void updateRole(Role role) throws RoleNotFoundException;

    /**
     * Updates {@link User}s of the {@link Role}.
     *
     * @param path    path
     * @param userIds id of users
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void updateUsers(String path, Long... userIds) throws RoleNotFoundException;

    /**
     * Updates {@link User}s of the {@link Group}.
     *
     * @param path      path
     * @param usernames usernames
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void updateUsers(String path, String... usernames) throws RoleNotFoundException;

    /**
     * Updates {@link Group}s of the {@link Role}.
     *
     * @param path     path
     * @param groupIds id of groups
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void updateGroups(String path, Long... groupIds) throws RoleNotFoundException;

    /**
     * Updates {@link Group}s of the {@link Role}.
     *
     * @param path       path
     * @param groupPaths path of groups
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void updateGroups(String path, String... groupPaths) throws RoleNotFoundException;

    /**
     * Removes the role.
     *
     * @param id identity of the role
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeRole(Long id) throws RoleNotFoundException;

    /**
     * Removes the role.
     *
     * @param path path
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeRole(String path) throws RoleNotFoundException;

    /**
     * Removes the {@link User}s from the {@link Role}.
     *
     * @param path    path
     * @param userIds id of users
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeUsers(String path, Long... userIds) throws RoleNotFoundException;

    /**
     * Removes the {@link User}s from the {@link Role}.
     *
     * @param path      path
     * @param usernames username of users
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeUsers(String path, String... usernames) throws RoleNotFoundException;

    /**
     * Removes the {@link Group}s from the {@link Role}.
     *
     * @param path     path
     * @param groupIds id of groups
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeGroups(String path, Long... groupIds) throws RoleNotFoundException;

    /**
     * Removes the {@link Group}s from the {@link Role}.
     *
     * @param path       path
     * @param groupPaths path of groups
     * @throws RoleNotFoundException throw when the entity is not found
     */
    void removeGroups(String path, String... groupPaths) throws RoleNotFoundException;

    /**
     * Checks if the {@link Role} exists.
     *
     * @param path path
     * @return true when the group with the specified path exists
     */
    boolean hasRole(String path);

    /**
     * Finds {@link Role} by path.
     *
     * @param id identity of the role
     * @return the role
     * @throws RoleNotFoundException throw when the entity is not found
     */
    Role findRole(Long id) throws RoleNotFoundException;

    /**
     * Finds {@link Role} by path.
     *
     * @param path path
     * @return the role
     * @throws RoleNotFoundException throw when the entity is not found
     */
    Role findRole(String path) throws RoleNotFoundException;

    /**
     * Finds {@link Role}s by wildcard condition.
     *
     * @param pathFilter pathFilter
     * @param pageable   pageable
     * @return page of roles
     */
    Page<Role> findRoles(String pathFilter, Pageable pageable);

    /**
     * Finds {@link Role}s.
     *
     * @param pageable pageable
     * @return page of roles
     */
    Page<Role> findRoles(Pageable pageable);

    /**
     * @return list of roles
     */
    List<Role> findAllRoles();

    /**
     * Finds all {@link User}s which belong to the {@link Role}.
     *
     * @param path path
     * @return list of users
     */
    List<User> findRoleUsers(String path);

    /**
     * Finds all {@link Group}s which belong to the {@link Role}.
     *
     * @param path path
     * @return list of groups
     */
    List<Group> findRoleGroups(String path);
}
