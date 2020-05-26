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
 * User manager.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface UserManager {
    /**
     * Adds new user.
     *
     * @param user user
     * @throws UserExistsException throw when the entity exists
     */
    void addUser(User user) throws UserExistsException;

    /**
     * Updates the user.
     *
     * @param user user
     * @throws UserNotFoundException throw when the entity is not found
     */
    void updateUser(User user) throws UserNotFoundException;

    /**
     * Updates {@link Group}s of the {@link User}.
     *
     * @param username   username
     * @param groupPaths paths of groups
     * @throws UserNotFoundException throw when the entity is not found
     */
    void updateGroups(String username, String... groupPaths) throws UserNotFoundException;

    /**
     * Updates {@link Group}s of the {@link User}.
     *
     * @param username username
     * @param groupIds ids of groups
     * @throws UserNotFoundException throw when the entity is not found
     */
    void updateGroups(String username, Long... groupIds) throws UserNotFoundException;

    /**
     * Updates {@link Role}s of the {@link User}.
     *
     * @param username  username
     * @param rolePaths paths of roles
     * @throws UserNotFoundException throw when the entity is not found
     */
    void updateRoles(String username, String... rolePaths) throws UserNotFoundException;

    /**
     * Updates {@link Role}s of the {@link User}.
     *
     * @param username username
     * @param roleIds  ids of roles
     * @throws UserNotFoundException throw when the entity is not found
     */
    void updateRoles(String username, Long... roleIds) throws UserNotFoundException;

    /**
     * Removes the user.
     *
     * @param id identity of the user
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeUser(Long id) throws UserNotFoundException;

    /**
     * Removes the user.
     *
     * @param username username
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeUser(String username) throws UserNotFoundException;

    /**
     * Removes the {@link Group}s from the {@link User}.
     *
     * @param username   username
     * @param groupPaths path of groups
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeGroups(String username, String... groupPaths) throws UserNotFoundException;

    /**
     * Removes the {@link Group}s from the {@link User}.
     *
     * @param username username
     * @param groupIds id of groups
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeGroups(String username, Long... groupIds) throws UserNotFoundException;

    /**
     * Removes the {@link Role}s from the {@link User}.
     *
     * @param username  username
     * @param rolePaths path of roles
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeRoles(String username, String... rolePaths) throws UserNotFoundException;

    /**
     * Removes the {@link Role}s from the {@link User}.
     *
     * @param username username
     * @param roleIds  id of roles
     * @throws UserNotFoundException throw when the entity is not found
     */
    void removeRoles(String username, Long... roleIds) throws UserNotFoundException;

    /**
     * Checks if the {@link User} exists.
     *
     * @param username username
     * @return true when the user with the specified username exists
     */
    boolean hasUser(String username);

    /**
     * Finds {@link User} by id.
     *
     * @param id identity of the user
     * @return the user
     * @throws UserNotFoundException throw when the entity is not found
     */
    User findUser(Long id) throws UserNotFoundException;

    /**
     * Finds {@link User} by username.
     *
     * @param username username
     * @return the role
     * @throws UserNotFoundException throw when the entity is not found
     */
    User findUser(String username) throws UserNotFoundException;

    /**
     * Finds {@link User}s by wildcard condition.
     *
     * @param usernameFilter usernameFilter
     * @param pageable       pageable
     * @return page of users
     */
    Page<User> findUsers(String usernameFilter, Pageable pageable);

    /**
     * Finds all {@link User}s.
     *
     * @return list of users.
     */
    List<User> findAllUsers();

    /**
     * Finds all {@link Group}s which belong to the {@link User}.
     *
     * @param username username
     * @return list of groups
     */
    List<Group> findUserGroups(String username);

    /**
     * Finds all {@link Role}s which belong to the {@link User}.
     *
     * @param username username
     * @return list of roles
     */
    List<Role> findUserRoles(String username);
}
