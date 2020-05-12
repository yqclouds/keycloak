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

import com.hsbc.unified.iam.core.entity.Group;
import com.hsbc.unified.iam.core.entity.GroupAttribute;
import com.hsbc.unified.iam.core.entity.GroupRoleMapping;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.TypedQuery;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class GroupAdapter implements GroupModel, JpaModel<Group> {

    protected Group group;
    protected EntityManager em;
    protected RealmModel realm;

    public GroupAdapter(RealmModel realm, EntityManager em, Group group) {
        this.em = em;
        this.group = group;
        this.realm = realm;
    }

    public static Group toEntity(GroupModel model, EntityManager em) {
        if (model instanceof GroupAdapter) {
            return ((GroupAdapter) model).getEntity();
        }
        return em.getReference(Group.class, model.getId());
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
            Group parentEntity = toEntity(parent, em);
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
        TypedQuery<String> query = em.createNamedQuery("getGroupIdsByParent", String.class);
        query.setParameter("parent", group.getId());
        List<String> ids = query.getResultList();
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
            em.remove(attr);
            group.getAttributes().remove(attr);
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
        em.persist(attr);
        group.getAttributes().add(attr);
    }

    @Override
    public void removeAttribute(String name) {
        Iterator<GroupAttribute> it = group.getAttributes().iterator();
        while (it.hasNext()) {
            GroupAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                em.remove(attr);
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

    protected TypedQuery<GroupRoleMapping> getGroupRoleMappingEntityTypedQuery(RoleModel role) {
        TypedQuery<GroupRoleMapping> query = em.createNamedQuery("groupHasRole", GroupRoleMapping.class);
        query.setParameter("group", getEntity());
        query.setParameter("roleId", role.getId());
        return query;
    }

    @Override
    public void grantRole(RoleModel role) {
        if (hasRole(role)) return;
        GroupRoleMapping entity = new GroupRoleMapping();
        entity.setGroup(getEntity());
        entity.setRoleId(role.getId());
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public Set<RoleModel> getRealmRoleMappings() {
        Set<RoleModel> roleMappings = getRoleMappings();

        Set<RoleModel> realmRoles = new HashSet<RoleModel>();
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
        TypedQuery<String> query = em.createNamedQuery("groupRoleMappingIds", String.class);
        query.setParameter("group", getEntity());
        List<String> ids = query.getResultList();
        Set<RoleModel> roles = new HashSet<RoleModel>();
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

        TypedQuery<GroupRoleMapping> query = getGroupRoleMappingEntityTypedQuery(role);
        query.setLockMode(LockModeType.PESSIMISTIC_WRITE);
        List<GroupRoleMapping> results = query.getResultList();
        if (results.size() == 0) return;
        for (GroupRoleMapping entity : results) {
            em.remove(entity);
        }
        em.flush();
    }

    @Override
    public Set<RoleModel> getClientRoleMappings(ClientModel app) {
        Set<RoleModel> roleMappings = getRoleMappings();

        Set<RoleModel> roles = new HashSet<RoleModel>();
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
        if (o == null || !(o instanceof GroupModel)) return false;

        GroupModel that = (GroupModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }


}
