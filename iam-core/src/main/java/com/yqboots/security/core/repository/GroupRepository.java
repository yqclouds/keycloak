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

import com.yqboots.security.core.Group;
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
 * {@link Group} repository.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface GroupRepository extends JpaRepository<Group, Long>, JpaSpecificationExecutor<Group> {
    /**
     * Deletes the group by its path.
     *
     * @param path path
     */
    @Transactional
    @Query("delete from #{#entityName} where path = ?1")
    @Modifying
    void delete(final String path);

    /**
     * Checks if the Group with the specified path exists.
     *
     * @param path path
     * @return true if exists.
     */
    @Query("select case when count(0) > 0 then true else false end from #{#entityName} where path = ?1")
    boolean exists(String path);

    /**
     * Finds by path.
     *
     * @param path path
     * @return Group
     */
    Group findByPath(String path);

    /**
     * Finds by username of users.
     *
     * @param username username
     * @return list of Group
     */
    List<Group> findByUsersUsername(final String username);

    /**
     * Finds by username of users.
     *
     * @param usernames usernames
     * @return list of Group
     */
    List<Group> findByUsersUsernameIn(final Collection<String> usernames);

    /**
     * Finds by path of roles.
     *
     * @param rolePath path of the role
     * @return list of Group
     */
    List<Group> findByRolesPath(final String rolePath);

    /**
     * Finds by path of roles.
     *
     * @param rolePaths path of the roles
     * @return list of Group
     */
    List<Group> findByRolesPathIn(final Collection<String> rolePaths);

    /**
     * Finds by paths.
     *
     * @param paths path of groups
     * @return list of Group
     */
    List<Group> findByPathIn(Collection<String> paths);

    /**
     * Finds by wildcard path, ignore case.
     *
     * @param pathFilter pathFilter
     * @return list of Group
     */
    List<Group> findByPathLikeIgnoreCase(String pathFilter);

    /**
     * Finds by wildcard path, ignore case.
     *
     * @param pathFilter pathFilter
     * @param pageable   pageable
     * @return page of Group
     */
    Page<Group> findByPathLikeIgnoreCase(String pathFilter, Pageable pageable);
}
