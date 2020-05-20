/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.models.jpa;

import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.facade.model.JpaModel;
import com.hsbc.unified.iam.repository.*;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.criteria.Join;
import javax.persistence.criteria.Predicate;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserAdapter implements UserModel, JpaModel<User> {

    protected User user;
    protected RealmModel realm;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserAttributeRepository userAttributeRepository;
    @Autowired
    private UserRequiredActionRepository userRequiredActionRepository;
    @Autowired
    private UserGroupMembershipRepository userGroupMembershipRepository;
    @Autowired
    private UserRoleMappingRepository userRoleMappingRepository;

    public UserAdapter(RealmModel realm, User user) {
        this.user = user;
        this.realm = realm;
    }

    @Override
    public User getEntity() {
        return user;
    }

    @Override
    public String getId() {
        return user.getId();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public void setUsername(String username) {
        username = KeycloakModelUtils.toLowerCaseSafe(username);
        user.setUsername(username);
    }

    @Override
    public Long getCreatedTimestamp() {
        return user.getCreatedTimestamp();
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
        user.setCreatedTimestamp(timestamp);
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        user.setEnabled(enabled);
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        if (value == null) {
            user.getAttributes().removeIf(a -> a.getName().equals(name));
        } else {
            String firstExistingAttrId = null;
            List<UserAttribute> toRemove = new ArrayList<>();
            for (UserAttribute attr : user.getAttributes()) {
                if (attr.getName().equals(name)) {
                    if (firstExistingAttrId == null) {
                        attr.setValue(value);
                        firstExistingAttrId = attr.getId();
                    } else {
                        toRemove.add(attr);
                    }
                }
            }

            if (firstExistingAttrId != null) {
                // Remove attributes through HQL to avoid StaleUpdateException
                userAttributeRepository.deleteUserAttributesByNameAndUserOtherThan(user.getId(), name, firstExistingAttrId);
                // Remove attribute from local entity
                user.getAttributes().removeAll(toRemove);
            } else {
                persistAttributeValue(name, value);
            }
        }
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        // Remove all existing
        removeAttribute(name);
        for (Iterator<String> it = values.stream().filter(Objects::nonNull).iterator(); it.hasNext(); ) {
            persistAttributeValue(name, it.next());
        }
    }

    private void persistAttributeValue(String name, String value) {
        UserAttribute attr = new UserAttribute();
        attr.setId(KeycloakModelUtils.generateId());
        attr.setName(name);
        attr.setValue(value);
        attr.setUser(user);
        userAttributeRepository.save(attr);
        user.getAttributes().add(attr);
        userRepository.saveAndFlush(user);
    }

    @Override
    public void removeAttribute(String name) {
        // KEYCLOAK-3296 : Remove attribute through HQL to avoid StaleUpdateException
        userAttributeRepository.deleteUserAttributesByNameAndUser(user.getId(), name);
        // KEYCLOAK-3494 : Also remove attributes from local user entity
        List<UserAttribute> toRemove = new ArrayList<>();
        for (UserAttribute attr : user.getAttributes()) {
            if (attr.getName().equals(name)) {
                toRemove.add(attr);
            }
        }
        user.getAttributes().removeAll(toRemove);
        userRepository.saveAndFlush(user);
    }

    @Override
    public String getFirstAttribute(String name) {
        for (UserAttribute attr : user.getAttributes()) {
            if (attr.getName().equals(name)) {
                return attr.getValue();
            }
        }
        return null;
    }

    @Override
    public List<String> getAttribute(String name) {
        List<String> result = new ArrayList<>();
        for (UserAttribute attr : user.getAttributes()) {
            if (attr.getName().equals(name)) {
                result.add(attr.getValue());
            }
        }
        return result;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> result = new MultivaluedHashMap<>();
        for (UserAttribute attr : user.getAttributes()) {
            result.add(attr.getName(), attr.getValue());
        }
        return result;
    }

    @Override
    public Set<String> getRequiredActions() {
        Set<String> result = new HashSet<>();
        for (UserRequiredAction attr : user.getRequiredActions()) {
            result.add(attr.getAction());
        }
        return result;
    }

    @Override
    public void addRequiredAction(RequiredAction action) {
        String actionName = action.name();
        addRequiredAction(actionName);
    }

    @Override
    public void addRequiredAction(String actionName) {
        for (UserRequiredAction attr : user.getRequiredActions()) {
            if (attr.getAction().equals(actionName)) {
                return;
            }
        }
        UserRequiredAction attr = new UserRequiredAction();
        attr.setAction(actionName);
        attr.setUser(user);
        userRequiredActionRepository.save(attr);
        user.getRequiredActions().add(attr);
        userRepository.saveAndFlush(user);
    }

    @Override
    public void removeRequiredAction(RequiredAction action) {
        String actionName = action.name();
        removeRequiredAction(actionName);
    }

    @Override
    public void removeRequiredAction(String actionName) {
        Iterator<UserRequiredAction> it = user.getRequiredActions().iterator();
        while (it.hasNext()) {
            UserRequiredAction attr = it.next();
            if (attr.getAction().equals(actionName)) {
                it.remove();
                userRequiredActionRepository.delete(attr);
            }
        }
    }

    @Override
    public String getFirstName() {
        return user.getFirstName();
    }

    @Override
    public void setFirstName(String firstName) {
        user.setFirstName(firstName);
    }

    @Override
    public String getLastName() {
        return user.getLastName();
    }

    @Override
    public void setLastName(String lastName) {
        user.setLastName(lastName);
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

    @Override
    public void setEmail(String email) {
        email = KeycloakModelUtils.toLowerCaseSafe(email);
        user.setEmail(email, realm.isDuplicateEmailsAllowed());
    }

    @Override
    public boolean isEmailVerified() {
        return user.isEmailVerified();
    }

    @Override
    public void setEmailVerified(boolean verified) {
        user.setEmailVerified(verified);
    }

    private Specification<UserGroupMembership> createGetGroupsQuerySpecification(String search) {
        return (Specification<UserGroupMembership>) (root, qb, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("user"), getEntity()));
            Join<UserGroupMembership, Group> join = root.join("group");
            if (Objects.nonNull(search) && !search.isEmpty()) {
                predicates.add(cb.like(cb.lower(join.get("name")), cb.lower(cb.literal("%" + search + "%"))));
            }

            qb.select(root.get("groupId"));
            qb.where(predicates.toArray(new Predicate[0]));
            qb.orderBy(cb.asc(join.get("name")));

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    public Set<GroupModel> getGroups() {
        List<UserGroupMembership> results = userGroupMembershipRepository.findAll(createGetGroupsQuerySpecification(null));

        Set<GroupModel> groups = new LinkedHashSet<>();
        for (UserGroupMembership membership : results) {
            groups.add(realm.getGroupById(membership.getGroupId()));
        }

        return groups;
    }

    @Override
    public Set<GroupModel> getGroups(String search, int first, int max) {
        List<UserGroupMembership> results = userGroupMembershipRepository.findAll(createGetGroupsQuerySpecification(null));

        Set<GroupModel> groups = new LinkedHashSet<>();
        for (UserGroupMembership membership : results) {
            groups.add(realm.getGroupById(membership.getGroupId()));
        }

        return groups;
    }

    @Override
    public long getGroupsCount() {
        List<UserGroupMembership> results = userGroupMembershipRepository.findAll(createGetGroupsQuerySpecification(null));
        return results.size();
    }

    @Override
    public long getGroupsCountByNameContaining(String search) {
        List<UserGroupMembership> results = userGroupMembershipRepository.findAll(createGetGroupsQuerySpecification(null));
        return results.size();
    }

    @Override
    public void joinGroup(GroupModel group) {
        if (isMemberOf(group)) return;
        joinGroupImpl(group);

    }

    protected void joinGroupImpl(GroupModel group) {
        UserGroupMembership entity = new UserGroupMembership();
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        userGroupMembershipRepository.save(entity);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        if (user == null || group == null) return;
        List<UserGroupMembership> results = userGroupMembershipRepository.userMemberOf(getEntity(), group.getId());
        if (results.size() == 0) return;
        userGroupMembershipRepository.deleteAll(results);
    }

    @Override
    public boolean isMemberOf(GroupModel group) {
        Set<GroupModel> roles = getGroups();
        return RoleUtils.isMember(roles, group);
    }

    @Override
    public boolean hasRole(RoleModel role) {
        Set<RoleModel> roles = getRoleMappings();
        return RoleUtils.hasRole(roles, role)
                || RoleUtils.hasRoleFromGroup(getGroups(), role, true);
    }

    @Override
    public void grantRole(RoleModel role) {
        if (hasRole(role)) return;
        grantRoleImpl(role);
    }

    public void grantRoleImpl(RoleModel role) {
        UserRoleMapping entity = new UserRoleMapping();
        entity.setUser(getEntity());
        entity.setRoleId(role.getId());
        userRoleMappingRepository.save(entity);
    }

    @Override
    public Set<RoleModel> getRealmRoleMappings() {
        Set<RoleModel> roleMappings = getRoleMappings();

        Set<RoleModel> realmRoles = new HashSet<>();
        for (RoleModel role : roleMappings) {
            RoleContainerModel container = role.getContainer();
            if (container instanceof RealmModel) {
                realmRoles.add(role);
            }
        }
        return realmRoles;
    }


    @Override
    public Set<RoleModel> getRoleMappings() {
        // we query ids only as the role might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        List<String> ids = userRoleMappingRepository.userRoleMappingIds(getEntity());
        Set<RoleModel> roles = new HashSet<>();
        for (String roleId : ids) {
            RoleModel roleById = realm.getRoleById(roleId);
            if (roleById == null) continue;
            roles.add(roleById);
        }
        return roles;
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        if (user == null || role == null) return;
        List<UserRoleMapping> results = userRoleMappingRepository.userHasRole(getEntity(), role.getId());
        if (results.size() == 0) return;
        userRoleMappingRepository.deleteAll(results);
    }

    @Override
    public Set<RoleModel> getClientRoleMappings(ClientModel app) {
        Set<RoleModel> roleMappings = getRoleMappings();

        Set<RoleModel> roles = new HashSet<>();
        for (RoleModel role : roleMappings) {
            RoleContainerModel container = role.getContainer();
            if (container instanceof ClientModel) {
                ClientModel appModel = (ClientModel) container;
                if (appModel.getId().equals(app.getId())) {
                    roles.add(role);
                }
            }
        }
        return roles;
    }

    @Override
    public String getFederationLink() {
        return user.getFederationLink();
    }

    @Override
    public void setFederationLink(String link) {
        user.setFederationLink(link);
    }

    @Override
    public String getServiceAccountClientLink() {
        return user.getServiceAccountClientLink();
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {
        user.setServiceAccountClientLink(clientInternalId);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserModel)) return false;

        UserModel that = (UserModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }


}
