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

import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.facade.model.JpaModel;
import com.hsbc.unified.iam.repository.ClientScopeAttributeRepository;
import com.hsbc.unified.iam.repository.ClientScopeRepository;
import com.hsbc.unified.iam.repository.ClientScopeRoleMappingRepository;
import com.hsbc.unified.iam.repository.ProtocolMapperRepository;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClientScopeAdapter implements ClientScopeModel, JpaModel<ClientScope> {

    protected RealmModel realm;
    protected ClientScope entity;

    @Autowired
    private RoleAdapter roleAdapter;

    @Autowired
    private ClientScopeRepository clientScopeRepository;
    @Autowired
    private ProtocolMapperRepository protocolMapperRepository;
    @Autowired
    private ClientScopeAttributeRepository clientScopeAttributeRepository;
    @Autowired
    private ClientScopeRoleMappingRepository clientScopeRoleMappingRepository;

    @Autowired
    private UserProvider userProvider;

    public ClientScopeAdapter(RealmModel realm, ClientScope entity) {
        this.realm = realm;
        this.entity = entity;
    }

    public ClientScope toClientScopeEntity(ClientScopeModel model) {
        if (model instanceof ClientScopeAdapter) {
            return ((ClientScopeAdapter) model).getEntity();
        }
        return clientScopeRepository.getOne(model.getId());
    }

    public ClientScope getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public String getName() {
        return entity.getName();
    }

    @Override
    public void setName(String name) {
        name = KeycloakModelUtils.convertClientScopeName(name);
        entity.setName(name);
    }

    @Override
    public String getDescription() {
        return entity.getDescription();
    }

    @Override
    public void setDescription(String description) {
        entity.setDescription(description);
    }

    @Override
    public String getProtocol() {
        return entity.getProtocol();
    }

    @Override
    public void setProtocol(String protocol) {
        entity.setProtocol(protocol);

    }

    @Override
    public Set<ProtocolMapperModel> getProtocolMappers() {
        Set<ProtocolMapperModel> mappings = new HashSet<>();
        for (ProtocolMapper entity : this.entity.getProtocolMappers()) {
            ProtocolMapperModel mapping = new ProtocolMapperModel();
            mapping.setId(entity.getId());
            mapping.setName(entity.getName());
            mapping.setProtocol(entity.getProtocol());
            mapping.setProtocolMapper(entity.getProtocolMapper());
            Map<String, String> config = new HashMap<>();
            if (entity.getConfig() != null) {
                config.putAll(entity.getConfig());
            }
            mapping.setConfig(config);
            mappings.add(mapping);
        }
        return mappings;
    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (getProtocolMapperByName(model.getProtocol(), model.getName()) != null) {
            throw new ModelDuplicateException("Protocol mapper name must be unique per protocol");
        }
        String id = model.getId() != null ? model.getId() : KeycloakModelUtils.generateId();
        ProtocolMapper entity = new ProtocolMapper();
        entity.setId(id);
        entity.setName(model.getName());
        entity.setProtocol(model.getProtocol());
        entity.setProtocolMapper(model.getProtocolMapper());
        entity.setClientScope(this.entity);
        entity.setConfig(model.getConfig());

        protocolMapperRepository.save(entity);
        this.entity.getProtocolMappers().add(entity);
        return entityToModel(entity);
    }

    protected ProtocolMapper getProtocolMapperEntity(String id) {
        for (ProtocolMapper entity : this.entity.getProtocolMappers()) {
            if (entity.getId().equals(id)) {
                return entity;
            }
        }
        return null;

    }

    protected ProtocolMapper getProtocolMapperEntityByName(String protocol, String name) {
        for (ProtocolMapper entity : this.entity.getProtocolMappers()) {
            if (entity.getProtocol().equals(protocol) && entity.getName().equals(name)) {
                return entity;
            }
        }
        return null;

    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        ProtocolMapper toDelete = getProtocolMapperEntity(mapping.getId());
        if (toDelete != null) {
            userProvider.preRemove(mapping);
            this.entity.getProtocolMappers().remove(toDelete);
            protocolMapperRepository.delete(toDelete);
        }
    }

    @Override
    public void updateProtocolMapper(ProtocolMapperModel mapping) {
        ProtocolMapper entity = getProtocolMapperEntity(mapping.getId());
        entity.setProtocolMapper(mapping.getProtocolMapper());
        if (entity.getConfig() == null) {
            entity.setConfig(mapping.getConfig());
        } else {
            entity.getConfig().clear();
            entity.getConfig().putAll(mapping.getConfig());
        }
        protocolMapperRepository.save(entity);
    }

    @Override
    public ProtocolMapperModel getProtocolMapperById(String id) {
        ProtocolMapper entity = getProtocolMapperEntity(id);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    @Override
    public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
        ProtocolMapper entity = getProtocolMapperEntityByName(protocol, name);
        if (entity == null) return null;
        return entityToModel(entity);
    }

    protected ProtocolMapperModel entityToModel(ProtocolMapper entity) {
        ProtocolMapperModel mapping = new ProtocolMapperModel();
        mapping.setId(entity.getId());
        mapping.setName(entity.getName());
        mapping.setProtocol(entity.getProtocol());
        mapping.setProtocolMapper(entity.getProtocolMapper());
        Map<String, String> config = new HashMap<>();
        if (entity.getConfig() != null) config.putAll(entity.getConfig());
        mapping.setConfig(config);
        return mapping;
    }

    @Override
    public Set<RoleModel> getRealmScopeMappings() {
        Set<RoleModel> roleMappings = getScopeMappings();

        Set<RoleModel> appRoles = new HashSet<>();
        for (RoleModel role : roleMappings) {
            RoleContainerModel container = role.getContainer();
            if (container instanceof RealmModel) {
                if (container.getId().equals(realm.getId())) {
                    appRoles.add(role);
                }
            }
        }

        return appRoles;
    }

    @Override
    public Set<RoleModel> getScopeMappings() {
        List<String> ids = clientScopeRoleMappingRepository.clientScopeRoleMappingIds(getEntity());
        Set<RoleModel> roles = new HashSet<>();
        for (String roleId : ids) {
            RoleModel role = realm.getRoleById(roleId);
            if (role == null) continue;
            roles.add(role);
        }
        return roles;
    }

    @Override
    public void addScopeMapping(RoleModel role) {
        if (hasScope(role)) return;
        ClientScopeRoleMapping entity = new ClientScopeRoleMapping();
        entity.setClientScope(getEntity());
        Role roleEntity = roleAdapter.toRoleEntity(role);
        entity.setRole(roleEntity);
        clientScopeRoleMappingRepository.save(entity);
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        Role roleEntity = roleAdapter.toRoleEntity(role);
        List<ClientScopeRoleMapping> results = clientScopeRoleMappingRepository.clientScopeHasRole(getEntity(), roleEntity);
        if (results.isEmpty()) return;

        clientScopeRoleMappingRepository.deleteAll(results);
    }

    @Override
    public boolean hasScope(RoleModel role) {
        Set<RoleModel> roles = getScopeMappings();
        if (roles.contains(role)) return true;

        for (RoleModel mapping : roles) {
            if (mapping.hasRole(role)) return true;
        }
        return false;
    }

    @Override
    public void setAttribute(String name, String value) {
        for (ClientScopeAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                attr.setValue(value);
                return;
            }
        }

        ClientScopeAttribute attr = new ClientScopeAttribute();
        attr.setName(name);
        attr.setValue(value);
        attr.setClientScope(entity);
        clientScopeAttributeRepository.save(attr);
        entity.getAttributes().add(attr);
        clientScopeRepository.save(entity);
    }

    @Override
    public void removeAttribute(String name) {
        Iterator<ClientScopeAttribute> it = entity.getAttributes().iterator();
        while (it.hasNext()) {
            ClientScopeAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                clientScopeAttributeRepository.delete(attr);
            }
        }
    }

    @Override
    public String getAttribute(String name) {
        return getAttributes().get(name);
    }

    @Override
    public Map<String, String> getAttributes() {
        Map<String, String> attrs = new HashMap<>();
        for (ClientScopeAttribute attr : entity.getAttributes()) {
            attrs.put(attr.getName(), attr.getValue());
        }
        return attrs;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientScopeModel)) return false;

        ClientScopeModel that = (ClientScopeModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }


}
