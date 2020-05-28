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
import com.hsbc.unified.iam.security.core.audit.SecurityAudit;
import com.hsbc.unified.iam.security.core.audit.annotation.Auditable;
import com.hsbc.unified.iam.security.core.repository.GroupRepository;
import com.hsbc.unified.iam.security.core.repository.RoleRepository;
import com.hsbc.unified.iam.security.core.repository.UserRepository;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Role manager implementation.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Service
@Transactional(readOnly = true)
public class RoleManagerImpl implements RoleManager {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RoleRepository roleRepository;

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_ADD_ROLE)
    public void addRole(final Role role) throws RoleExistsException {
        Assert.isTrue(role.isNew());
        Assert.hasText(role.getPath());

        if (roleRepository.exists(role.getPath())) {
            throw new RoleExistsException(role.getPath());
        }

        roleRepository.save(role);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_ROLE)
    public void updateRole(final Role role) throws RoleNotFoundException {
        Assert.isTrue(!role.isNew());
        Assert.hasText(role.getPath());

        final Role entity = roleRepository.findByPath(role.getPath());
        if (entity == null) {
            throw new RoleNotFoundException(role.getPath());
        }

        entity.setAlias(role.getAlias());
        entity.setDescription(role.getDescription());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_USERS_OF_ROLE)
    public void updateUsers(final String path, final Long... userIds) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final Set<User> roleUsers = role.getUsers();
        if (CollectionUtils.isNotEmpty(roleUsers)) {
            roleUsers.forEach(user -> user.getRoles().remove(role));
        }

        if (ArrayUtils.isNotEmpty(userIds)) {
            final List<User> users = userRepository.findAllById(Arrays.asList(userIds));
            users.forEach(user -> user.getRoles().add(role));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_USERS_OF_ROLE)
    public void updateUsers(final String path, final String... usernames) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final Set<User> roleUsers = role.getUsers();
        if (CollectionUtils.isNotEmpty(roleUsers)) {
            roleUsers.stream().forEach(user -> user.getRoles().remove(role));
        }

        if (ArrayUtils.isNotEmpty(usernames)) {
            final List<User> users = userRepository.findByUsernameIn(Arrays.asList(usernames));
            users.stream().forEach(user -> user.getRoles().add(role));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_GROUPS_OF_ROLE)
    public void updateGroups(final String path, final Long... groupIds) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final Set<Group> roleGroups = role.getGroups();
        if (CollectionUtils.isNotEmpty(roleGroups)) {
            roleGroups.forEach(group -> group.getRoles().remove(role));
        }

        if (ArrayUtils.isNotEmpty(groupIds)) {
            final List<Group> groups = groupRepository.findAllById(Arrays.asList(groupIds));
            groups.forEach(group -> group.getRoles().add(role));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_UPDATE_GROUPS_OF_ROLE)
    public void updateGroups(final String path, final String... groupPaths) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final Set<Group> roleGroups = role.getGroups();
        if (CollectionUtils.isNotEmpty(roleGroups)) {
            roleGroups.forEach(group -> group.getRoles().remove(role));
        }

        if (ArrayUtils.isNotEmpty(groupPaths)) {
            final List<Group> groups = groupRepository.findByPathIn(Arrays.asList(groupPaths));
            groups.forEach(group -> group.getRoles().add(role));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_ROLE)
    public void removeRole(final Long id) throws RoleNotFoundException {
        Assert.notNull(id);

        final Optional<Role> optional = roleRepository.findById(id);
        if (!optional.isPresent()) {
            throw new RoleNotFoundException(Long.toString(id));
        }

        final List<User> users = userRepository.findByRolesPath(optional.get().getPath());
        users.forEach(user -> user.getRoles().remove(optional.get()));

        final List<Group> groups = groupRepository.findByRolesPath(optional.get().getPath());
        groups.forEach(group -> group.getRoles().remove(optional.get()));

        roleRepository.delete(optional.get());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_ROLE)
    public void removeRole(final String path) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final List<User> users = userRepository.findByRolesPath(role.getPath());
        users.forEach(user -> user.getRoles().remove(role));

        final List<Group> groups = groupRepository.findByRolesPath(role.getPath());
        groups.forEach(group -> group.getRoles().remove(role));

        roleRepository.delete(role);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_USERS_FROM_ROLE)
    public void removeUsers(final String path, final Long... userIds) throws RoleNotFoundException {
        Assert.hasText(path);
        Assert.notEmpty(userIds);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final List<User> users = userRepository.findByRolesPath(role.getPath());
        users.stream().filter(user -> ArrayUtils.contains(userIds, user.getId()))
                .forEach(user -> user.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_USERS_FROM_ROLE)
    public void removeUsers(final String path, final String... usernames) throws RoleNotFoundException {
        Assert.hasText(path);
        Assert.notEmpty(usernames);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final List<User> users = userRepository.findByRolesPath(role.getPath());
        users.stream().filter(user -> ArrayUtils.contains(usernames, user.getUsername()))
                .forEach(user -> user.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_GROUPS_FROM_ROLE)
    public void removeGroups(final String path, final Long... groupIds) throws RoleNotFoundException {
        Assert.hasText(path);
        Assert.notEmpty(groupIds);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final List<Group> groups = groupRepository.findByRolesPath(role.getPath());
        groups.stream().filter(group -> ArrayUtils.contains(groupIds, group.getId()))
                .forEach(group -> group.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    @Auditable(code = SecurityAudit.CODE_REMOVE_GROUPS_FROM_ROLE)
    public void removeGroups(final String path, final String... groupPaths) throws RoleNotFoundException {
        Assert.hasText(path);
        Assert.notEmpty(groupPaths);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        final List<Group> groups = groupRepository.findByRolesPath(role.getPath());
        groups.stream().filter(group -> ArrayUtils.contains(groupPaths, group.getPath()))
                .forEach(group -> group.getRoles().remove(role));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasRole(final String path) {
        return roleRepository.exists(path);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Role findRole(final Long id) throws RoleNotFoundException {
        Assert.notNull(id);

        final Optional<Role> optional = roleRepository.findById(id);
        if (!optional.isPresent()) {
            throw new RoleNotFoundException(Long.toString(id));
        }

        return optional.get();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Role findRole(final String path) throws RoleNotFoundException {
        Assert.hasText(path);

        final Role role = roleRepository.findByPath(path);
        if (role == null) {
            throw new RoleNotFoundException(path);
        }

        return role;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<Role> findRoles(final String pathFilter, final Pageable pageable) {
        return roleRepository.findByPathLikeIgnoreCase(DBUtils.wildcard(pathFilter), pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<Role> findRoles(final Pageable pageable) {
        return roleRepository.findAll(pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Role> findAllRoles() {
        return roleRepository.findAll();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<User> findRoleUsers(final String path) {
        return userRepository.findByRolesPath(path);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Group> findRoleGroups(final String path) {
        return groupRepository.findByRolesPath(path);
    }
}
