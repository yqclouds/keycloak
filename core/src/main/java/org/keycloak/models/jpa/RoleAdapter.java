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

import com.hsbc.unified.iam.entity.Role;
import com.hsbc.unified.iam.entity.RoleAttribute;
import com.hsbc.unified.iam.repository.RoleAttributeRepository;
import com.hsbc.unified.iam.repository.RoleRepository;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RoleAdapter implements RoleModel, JpaModel<Role> {
    protected Role role;
    protected RealmModel realm;
    protected KeycloakSession session;

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private RoleAttributeRepository roleAttributeRepository;

    public RoleAdapter(KeycloakSession session, RealmModel realm, Role role) {
        this.realm = realm;
        this.role = role;
        this.session = session;
    }

    public Role toRoleEntity(RoleModel model) {
        if (model instanceof RoleAdapter) {
            return ((RoleAdapter) model).getEntity();
        }

        return roleRepository.getOne(model.getId());
    }

    public Role getEntity() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    @Override
    public String getName() {
        return role.getName();
    }

    @Override
    public void setName(String name) {
        role.setName(name);
    }

    @Override
    public String getDescription() {
        return role.getDescription();
    }

    @Override
    public void setDescription(String description) {
        role.setDescription(description);
    }

    @Override
    public String getId() {
        return role.getId();
    }

    @Override
    public boolean isComposite() {
        return getComposites().size() > 0;
    }

    @Override
    public void addCompositeRole(RoleModel role) {
        Role entity = this.toRoleEntity(role);
        for (Role composite : getEntity().getCompositeRoles()) {
            if (composite.equals(entity)) return;
        }
        getEntity().getCompositeRoles().add(entity);
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        Role entity = this.toRoleEntity(role);
        getEntity().getCompositeRoles().remove(entity);
    }

    @Override
    public Set<RoleModel> getComposites() {
        Set<RoleModel> set = new HashSet<>();

        for (Role composite : getEntity().getCompositeRoles()) {
            set.add(new RoleAdapter(session, realm, composite));

            // todo I want to do this, but can't as you get stack overflow
            // set.add(session.realms().getRoleById(composite.getId(), realm));
        }
        return set;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        return this.equals(role) || KeycloakModelUtils.searchFor(role, this, new HashSet<>());
    }

    private void persistAttributeValue(String name, String value) {
        RoleAttribute attr = new RoleAttribute();
        attr.setId(KeycloakModelUtils.generateId());
        attr.setName(name);
        attr.setValue(value);
        attr.setRole(role);
        roleAttributeRepository.save(attr);
        role.getAttributes().add(attr);
        roleRepository.saveAndFlush(role);
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        setAttribute(name, Collections.singletonList(value));
    }

    @Override
    public void setAttribute(String name, Collection<String> values) {
        removeAttribute(name);

        for (String value : values) {
            persistAttributeValue(name, value);
        }
    }

    @Override
    public void removeAttribute(String name) {
        Collection<RoleAttribute> attributes = role.getAttributes();
        if (attributes == null) {
            return;
        }

        roleAttributeRepository.deleteRoleAttributesByNameAndUser(role.getId(), name);
        attributes.removeIf(attribute -> attribute.getName().equals(name));
        roleRepository.save(role);
    }

    @Override
    public String getFirstAttribute(String name) {
        for (RoleAttribute attribute : role.getAttributes()) {
            if (attribute.getName().equals(name)) {
                return attribute.getValue();
            }
        }

        return null;
    }

    @Override
    public List<String> getAttribute(String name) {
        List<String> attributes = new ArrayList<>();
        for (RoleAttribute attribute : role.getAttributes()) {
            if (attribute.getName().equals(name)) {
                attributes.add(attribute.getValue());
            }
        }
        return attributes;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> map = new HashMap<>();
        for (RoleAttribute attribute : role.getAttributes()) {
            map.computeIfAbsent(attribute.getName(), name -> new ArrayList<>()).add(attribute.getValue());
        }

        return map;
    }

    @Override
    public boolean isClientRole() {
        return role.isClientRole();
    }

    @Override
    public String getContainerId() {
        if (isClientRole()) return role.getClient().getId();
        else return realm.getId();
    }

    @Override
    public RoleContainerModel getContainer() {
        if (role.isClientRole()) {
            return realm.getClientById(role.getClient().getId());

        } else {
            return realm;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RoleModel)) return false;

        RoleModel that = (RoleModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
