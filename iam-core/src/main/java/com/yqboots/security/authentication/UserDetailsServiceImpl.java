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
package com.yqboots.security.authentication;

import com.yqboots.security.core.Group;
import com.yqboots.security.core.Role;
import com.yqboots.security.core.User;
import com.yqboots.security.core.repository.GroupRepository;
import com.yqboots.security.core.repository.RoleRepository;
import com.yqboots.security.core.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.util.*;
import java.util.stream.Collectors;

/**
 * The dao implementation of {@link UserDetailsService}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class UserDetailsServiceImpl implements UserDetailsService {
    /**
     * The LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    /**
     * Checks if enabling authorities.
     */
    private boolean enableAuthorities = true;

    /**
     * Checks if enabling groups.
     */
    private boolean enableGroups = true;

    /**
     * userRepository
     */
    private UserRepository userRepository;

    /**
     * groupRepository
     */
    private GroupRepository groupRepository;

    /**
     * roleRepository
     */
    private RoleRepository roleRepository;

    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    /**
     * {@inheritDoc}
     */
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        Assert.hasLength(username, "username is required");
        User user = userRepository.findByUsername(username);
        if (user == null) {
            LOGGER.info("Query returned no results for user {}", username);
            throw new UsernameNotFoundException(messages.getMessage("JdbcDaoImpl.notFound", new String[]{username}));
        }

        Set<Role> allAuthorities = new HashSet<>();
        if (enableAuthorities) {
            allAuthorities.addAll(loadUserAuthorities(user.getUsername()));
        }

        if (enableGroups) {
            allAuthorities.addAll(loadGroupAuthorities(user.getUsername()));
        }

        addCustomAuthorities(user.getUsername(), allAuthorities);

        if (allAuthorities.size() == 0) {
            LOGGER.info("User {} has no authorities and will be treated as 'not found'", username);
            throw new UsernameNotFoundException(messages.getMessage("JdbcDaoImpl.notFound", new String[]{username}));
        }

        return createUserDetails(user, allAuthorities);
    }

    /**
     * Creates {@link UserDetails} based on {@link User} and its roles.
     *
     * @param userFromQuery       the {@link User}
     * @param combinedAuthorities all authorities for the specified user
     * @return {@link UserDetails}
     */
    protected UserDetails createUserDetails(User userFromQuery, Collection<Role> combinedAuthorities) {
        String returnUsername = userFromQuery.getUsername();

        return new User(userFromQuery.getId(), returnUsername, userFromQuery.getPassword(), userFromQuery.isEnabled(),
                new HashSet<>(combinedAuthorities));
    }

    /**
     * Loads authorities of the user.
     *
     * @param username username
     * @return roles belong to the user
     */
    protected List<Role> loadUserAuthorities(String username) {
        return roleRepository.findByUsersUsername(username);
    }

    /**
     * Loads the authorities of the groups which belong to the user.
     *
     * @param username username
     * @return roles belong to the user
     */
    protected List<Role> loadGroupAuthorities(String username) {
        List<Role> results = new ArrayList<>();

        final List<Group> groups = groupRepository.findByUsersUsername(username);

        if (!groups.isEmpty()) {
            Set<String> groupPaths = groups.stream().map(Group::getPath).collect(Collectors.toSet());

            results = roleRepository.findByGroupsPathIn(groupPaths);
        }

        return results;
    }

    /**
     * Customized authorities.
     *
     * @param username    username
     * @param authorities authorities
     */
    protected void addCustomAuthorities(String username, Collection<Role> authorities) {
    }

    public void setEnableAuthorities(final boolean enableAuthorities) {
        this.enableAuthorities = enableAuthorities;
    }

    public void setEnableGroups(final boolean enableGroups) {
        this.enableGroups = enableGroups;
    }

    public void setUserRepository(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void setGroupRepository(final GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    public void setRoleRepository(final RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }
}
