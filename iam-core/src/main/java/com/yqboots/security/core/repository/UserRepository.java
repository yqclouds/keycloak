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
package com.yqboots.security.core.repository;

import com.yqboots.security.core.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;

/**
 * {@link User} repository.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
    /**
     * Deletes the users by username.
     *
     * @param username username
     */
    @Transactional
    @Query("delete from #{#entityName} where username = ?1")
    @Modifying
    void delete(String username);

    /**
     * Checks if the Role with the specified username exists.
     *
     * @param username username
     * @return true if exists.
     */
    @Query("select case when count(0) > 0 then true else false end from #{#entityName} where username = ?1")
    boolean exists(String username);

    /**
     * Finds by username.
     *
     * @param username username
     * @return User
     */
    User findByUsername(String username);

    /**
     * Finds by username of users.
     *
     * @param usernames usernames
     * @return list of User
     */
    List<User> findByUsernameIn(final Collection<String> usernames);

    /**
     * Finds by path of the role.
     *
     * @param rolePath path of the role
     * @return list of User
     */
    List<User> findByRolesPath(final String rolePath);

    /**
     * Finds by path of roles.
     *
     * @param rolePaths path of the roles
     * @return list of User
     */
    List<User> findByRolesPathIn(final Collection<String> rolePaths);

    /**
     * Finds by path of group.
     *
     * @param groupPath path of the group
     * @return list of User
     */
    List<User> findByGroupsPath(final String groupPath);

    /**
     * Finds by path of groups.
     *
     * @param groupPaths path of the groups
     * @return list of User
     */
    List<User> findByGroupsPathIn(final Collection<String> groupPaths);

    /**
     * Finds by wildcard username, ignore case.
     *
     * @param usernameFilter usernameFilter
     * @return list of User
     */
    List<User> findByUsernameLikeIgnoreCase(String usernameFilter);

    /**
     * Finds by wildcard username, ignore case.
     *
     * @param usernameFilter usernameFilter
     * @param pageable       pageable
     * @return page of User
     */
    Page<User> findByUsernameLikeIgnoreCase(String usernameFilter, Pageable pageable);
}
