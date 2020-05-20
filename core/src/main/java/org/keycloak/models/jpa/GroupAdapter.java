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
import com.hsbc.unified.iam.entity.Group;
import com.hsbc.unified.iam.entity.GroupAttribute;
import com.hsbc.unified.iam.entity.GroupRoleMapping;
import com.hsbc.unified.iam.facade.model.JpaModel;
import com.hsbc.unified.iam.repository.GroupAttributeRepository;
import com.hsbc.unified.iam.repository.GroupRepository;
import com.hsbc.unified.iam.repository.GroupRoleMappingRepository;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class GroupAdapter implements GroupModel, JpaModel<Group> {

    protected Group group;
    protected RealmModel realm;

    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private GroupAttributeRepository groupAttributeRepository;
    @Autowired
    private GroupRoleMappingRepository groupRoleMappingRepository;

    public GroupAdapter(RealmModel realm, Group group) {
        this.group = group;
        this.realm = realm;
    }

    public Group toEntity(GroupModel model) {
        if (model instanceof GroupAdapter) {
            return ((GroupAdapter) model).getEntity();
        }

        return groupRepository.getOne(model.getId());
    }

    public Group getEntity() {
        return group;
    }

    @Override
    public String getId() {
        return group.getId();
    }

    @Override
    public String getName() {
        return group.getName();
    }

    @Override
    public void setName(String name) {
        group.setName(name);
    }

    @Override
    public GroupModel getParent() {
        String parentId = this.getParentId();
        return parentId == null ? null : realm.getGroupById(parentId);
    }

    @Override
    public void setParent(GroupModel parent) {
        if (parent == null) {
            group.setParentId(Group.TOP_PARENT_ID);
        } else if (!parent.getId().equals(getId())) {
            Group parentEntity = toEntity(parent);
            group.setParentId(parentEntity.getId());
        }
    }

    @Override
    public String getParentId() {
        return Group.TOP_PARENT_ID.equals(group.getParentId()) ? null : group.getParentId();
    }

    @Override
    public void addChild(GroupModel subGroup) {
        if (subGroup.getId().equals(getId())) {
            return;
        }
        subGroup.setParent(this);
    }

    @Override
    public void removeChild(GroupModel subGroup) {
        if (subGroup.getId().equals(getId())) {
            return;
        }
        subGroup.setParent(null);
    }

    @Override
    public Set<GroupModel> getSubGroups() {
        List<String> ids = groupRepository.getGroupIdsByParent(group.getId());
        Set<GroupModel> set = new HashSet<>();
        for (String id : ids) {
            GroupModel subGroup = realm.getGroupById(id);
            if (subGroup == null) continue;
            set.add(subGroup);
        }

        return set;
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        boolean found = false;
        List<GroupAttribute> toRemove = new ArrayList<>();
        for (GroupAttribute attr : group.getAttributes()) {
            if (attr.getName().equals(name)) {
                if (!found) {
                    attr.setValue(value);
                    found = true;
                } else {
                    toRemove.add(attr);
                }
            }
        }

        for (GroupAttribute attr : toRemove) {
            group.getAttributes().remove(attr);
            groupAttributeRepository.delete(attr);
        }

        if (found) {
            return;
        }

        persistAttributeValue(name, value);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        // Remove all existing
        removeAttribute(name);

        // Put all new
        for (String value : values) {
            persistAttributeValue(name, value);
        }
    }

    private void persistAttributeValue(String name, String value) {
        GroupAttribute attr = new GroupAttribute();
        attr.setId(KeycloakModelUtils.generateId());
        attr.setName(name);
        attr.setValue(value);
        attr.setGroup(group);
        groupAttributeRepository.save(attr);
        group.getAttributes().add(attr);
    }

    @Override
    public void removeAttribute(String name) {
        Iterator<GroupAttribute> it = group.getAttributes().iterator();
        while (it.hasNext()) {
            GroupAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                groupAttributeRepository.delete(attr);
            }
        }
    }

    @Override
    public String getFirstAttribute(String name) {
        for (GroupAttribute attr : group.getAttributes()) {
            if (attr.getName().equals(name)) {
                return attr.getValue();
            }
        }
        return null;
    }

    @Override
    public List<String> getAttribute(String name) {
        List<String> result = new ArrayList<>();
        for (GroupAttribute attr : group.getAttributes()) {
            if (attr.getName().equals(name)) {
                result.add(attr.getValue());
            }
        }
        return result;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> result = new MultivaluedHashMap<>();
        for (GroupAttribute attr : group.getAttributes()) {
            result.add(attr.getName(), attr.getValue());
        }
        return result;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        Set<RoleModel> roles = getRoleMappings();
        return RoleUtils.hasRole(roles, role);
    }

    @Override
    public void grantRole(RoleModel role) {
        if (hasRole(role)) return;
        GroupRoleMapping entity = new GroupRoleMapping();
        entity.setGroup(getEntity());
        entity.setRoleId(role.getId());
        groupRoleMappingRepository.save(entity);
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
        List<String> ids = groupRoleMappingRepository.findGroupRoleMappingIds(getEntity());
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
        if (group == null || role == null) return;
        List<GroupRoleMapping> results = groupRoleMappingRepository.isGroupHasRole(getEntity(), role.getId());
        if (results.size() == 0) return;
        groupRoleMappingRepository.deleteAll(results);
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GroupModel)) return false;

        GroupModel that = (GroupModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }


}
