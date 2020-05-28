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
package com.hsbc.unified.iam.security.core;

import com.hsbc.unified.iam.core.util.DBUtils;
import com.hsbc.unified.iam.security.autoconfigure.SecurityProperties;
import com.hsbc.unified.iam.security.context.UserRemovedEvent;
import com.hsbc.unified.iam.security.core.audit.SecurityAudit;
import com.hsbc.unified.iam.security.core.audit.annotation.Auditable;
import com.hsbc.unified.iam.security.core.repository.GroupRepository;
import com.hsbc.unified.iam.security.core.repository.RoleRepository;
import com.hsbc.unified.iam.security.core.repository.UserRepository;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.*;

/**
 * User manager implementation.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Service
@Transactional(readOnly = true)
public class UserManagerImpl implements UserManager, ApplicationEventPublisherAware {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired(required = false)
    private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

    @Autowired
    private SecurityProperties properties;

    private ApplicationEventPublisher applicationEventPublisher;

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_ADD_USER)
    public void addUser(final User user) throws UserExistsException {
        Assert.isTrue(user.isNew());
        Assert.hasText(user.getUsername());

        if (userRepository.exists(user.getUsername())) {
            throw new UserExistsException(user.getUsername());
        }

        user.setPassword(getPasswordDefault(user.getPassword()));

        userRepository.save(user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_USER)
    public void updateUser(final User user) throws UserNotFoundException {
        Assert.isTrue(!user.isNew());
        Assert.hasText(user.getUsername());

        final User entity = userRepository.findByUsername(user.getUsername());
        if (entity == null) {
            throw new UserNotFoundException(user.getUsername());
        }

        entity.setEnabled(user.isEnabled());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_GROUPS_OF_USER)
    public void updateGroups(final String username, final String... groupPaths) throws UserNotFoundException {
        Assert.hasText(username);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        // if groupPaths is empty, will remove all
        final Set<Group> userGroups = user.getGroups();
        if (CollectionUtils.isNotEmpty(userGroups)) {
            userGroups.clear();
        }

        if (ArrayUtils.isNotEmpty(groupPaths)) {
            final List<Group> groups = groupRepository.findByPathIn(Arrays.asList(groupPaths));
            if (!groups.isEmpty()) {
                user.setGroups(new HashSet<>(groups));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_GROUPS_OF_USER)
    public void updateGroups(final String username, final Long... groupIds) throws UserNotFoundException {
        Assert.hasText(username);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final Set<Group> userGroups = user.getGroups();
        if (CollectionUtils.isNotEmpty(userGroups)) {
            userGroups.clear();
        }

        if (ArrayUtils.isNotEmpty(groupIds)) {
            final List<Group> groups = groupRepository.findAllById(Arrays.asList(groupIds));
            if (!groups.isEmpty()) {
                user.setGroups(new HashSet<>(groups));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_ROLES_OF_USER)
    public void updateRoles(final String username, final String... rolePaths) throws UserNotFoundException {
        Assert.hasText(username);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final Set<Role> userRoles = user.getRoles();
        if (CollectionUtils.isNotEmpty(userRoles)) {
            userRoles.clear();
        }

        if (ArrayUtils.isNotEmpty(rolePaths)) {
            final List<Role> roles = roleRepository.findByPathIn(Arrays.asList(rolePaths));
            if (!roles.isEmpty()) {
                user.setRoles(new HashSet<>(roles));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_ROLES_OF_USER)
    public void updateRoles(final String username, final Long... roleIds) throws UserNotFoundException {
        Assert.hasText(username);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final Set<Role> userRoles = user.getRoles();
        if (CollectionUtils.isNotEmpty(userRoles)) {
            userRoles.clear();
        }

        if (ArrayUtils.isNotEmpty(roleIds)) {
            final List<Role> roles = roleRepository.findAllById(Arrays.asList(roleIds));
            if (!roles.isEmpty()) {
                user.setRoles(new HashSet<>(roles));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_USER)
    public void removeUser(final String username) throws UserNotFoundException {
        Assert.hasText(username);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        if (properties.getUser().isDisabledWhenRemoving()) {
            disableUser(user);
        } else {
            removeUser(user);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_USER)
    public void removeUser(final Long id) throws UserNotFoundException {
        Assert.notNull(id);

        final Optional<User> optional = userRepository.findById(id);
        if (!optional.isPresent()) {
            throw new UserNotFoundException(Long.toString(id));
        }

        if (properties.getUser().isDisabledWhenRemoving()) {
            disableUser(optional.get());
        } else {
            removeUser(optional.get());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_GROUPS_FROM_USER)
    public void removeGroups(final String username, final String... groupPaths) throws UserNotFoundException {
        Assert.hasText(username);
        Assert.notEmpty(groupPaths);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final List<Group> groups = groupRepository.findByPathIn(Arrays.asList(groupPaths));
        groups.stream().filter(group -> ArrayUtils.contains(groupPaths, group.getPath()))
                .forEach(group -> user.getGroups().remove(group));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_GROUPS_FROM_USER)
    public void removeGroups(final String username, final Long... groupIds) throws UserNotFoundException {
        Assert.hasText(username);
        Assert.notEmpty(groupIds);

        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final List<Group> groups = groupRepository.findAllById(Arrays.asList(groupIds));
        groups.stream().filter(group -> ArrayUtils.contains(groupIds, group.getId()))
                .forEach(group -> user.getGroups().remove(group));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_ROLES_FROM_USER)
    public void removeRoles(final String username, final String... rolePaths) throws UserNotFoundException {
        Assert.hasText(username);
        Assert.notEmpty(rolePaths);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final List<Role> roles = roleRepository.findByPathIn(Arrays.asList(rolePaths));
        roles.stream().filter(role -> ArrayUtils.contains(rolePaths, role.getPath()))
                .forEach(role -> user.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_ROLES_FROM_USER)
    public void removeRoles(final String username, final Long... roleIds) throws UserNotFoundException {
        Assert.hasText(username);
        Assert.notEmpty(roleIds);

        final User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(username);
        }

        final List<Role> roles = roleRepository.findAllById(Arrays.asList(roleIds));
        roles.stream().filter(role -> ArrayUtils.contains(roleIds, role.getId()))
                .forEach(role -> user.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasUser(final String username) {
        return userRepository.exists(username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User findUser(final Long id) throws UserNotFoundException {
        Assert.notNull(id);

        Optional<User> optional = userRepository.findById(id);
        if (!optional.isPresent()) {
            throw new UserNotFoundException(Long.toString(id));
        }

        return optional.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User findUser(final String username) throws UserNotFoundException {
        Assert.hasText(username);

        User result = userRepository.findByUsername(username);
        if (result == null) {
            throw new UserNotFoundException(username);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<User> findUsers(final String usernameFilter, final Pageable pageable) {
        return userRepository.findByUsernameLikeIgnoreCase(DBUtils.wildcard(usernameFilter), pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Group> findUserGroups(final String username) {
        return groupRepository.findByUsersUsername(username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Role> findUserRoles(final String username) {
        return roleRepository.findByUsersUsername(username);
    }

    @Override
    public void setApplicationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    /**
     * Gets the default password from configuration.
     *
     * @param password the password to set
     * @return the encoded password
     */
    private String getPasswordDefault(final String password) {
        String result = password;
        if (StringUtils.isBlank(result)) {
            // encrypt the password
            result = passwordEncoder.encode(properties.getUser().getPasswordDefault());
        }

        return result;
    }

    /**
     * Removes the user physically.
     *
     * @param user the removing user
     */
    private void removeUser(final User user) {
        // remove physically
        final String username = user.getUsername();
        userRepository.delete(user);

        applicationEventPublisher.publishEvent(new UserRemovedEvent(this, username));
    }

    /**
     * Disabled the user.
     *
     * @param user the disabling user
     */
    private void disableUser(final User user) {
        user.setEnabled(false);
        userRepository.save(user);
    }
}
