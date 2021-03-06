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
import com.hsbc.unified.iam.entity.events.ClientUpdatedEvent;
import com.hsbc.unified.iam.facade.model.JpaModel;
import com.hsbc.unified.iam.repository.*;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClientAdapter implements ClientModel, JpaModel<Client>, ApplicationEventPublisherAware {

    protected RealmModel realm;
    protected Client entity;

    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    @Autowired
    private RoleAdapter roleAdapter;
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private ClientScopeAdapter clientScopeAdapter;
    @Autowired
    private ClientAttributeRepository clientAttributeRepository;
    @Autowired
    private ClientScopeClientMappingRepository clientScopeClientMappingRepository;
    @Autowired
    private ProtocolMapperRepository protocolMapperRepository;

    @Autowired
    private UserProvider userProvider;
    @Autowired
    private RealmProvider realmProvider;

    public ClientAdapter(RealmModel realm, Client entity) {
        this.realm = realm;
        this.entity = entity;
    }

    public static boolean contains(String str, String[] array) {
        for (String s : array) {
            if (str.equals(s)) return true;
        }
        return false;
    }

    public Client getEntity() {
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
    public boolean isEnabled() {
        return entity.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        entity.setEnabled(enabled);
    }

    @Override
    public boolean isAlwaysDisplayInConsole() {
        return entity.isAlwaysDisplayInConsole();
    }

    @Override
    public void setAlwaysDisplayInConsole(boolean alwaysDisplayInConsole) {
        entity.setAlwaysDisplayInConsole(alwaysDisplayInConsole);
    }

    @Override
    public boolean isPublicClient() {
        return entity.isPublicClient();
    }

    @Override
    public void setPublicClient(boolean flag) {
        entity.setPublicClient(flag);
    }

    @Override
    public boolean isFrontchannelLogout() {
        return entity.isFrontchannelLogout();
    }

    @Override
    public void setFrontchannelLogout(boolean flag) {
        entity.setFrontchannelLogout(flag);
    }

    @Override
    public boolean isFullScopeAllowed() {
        return entity.isFullScopeAllowed();
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        entity.setFullScopeAllowed(value);
    }

    @Override
    public Set<String> getWebOrigins() {
        return new HashSet<>(entity.getWebOrigins());
    }

    @Override
    public void setWebOrigins(Set<String> webOrigins) {
        entity.setWebOrigins(webOrigins);
    }

    @Override
    public void addWebOrigin(String webOrigin) {
        entity.getWebOrigins().add(webOrigin);
    }

    @Override
    public void removeWebOrigin(String webOrigin) {
        entity.getWebOrigins().remove(webOrigin);
    }

    @Override
    public Set<String> getRedirectUris() {
        return new HashSet<>(entity.getRedirectUris());
    }

    @Override
    public void setRedirectUris(Set<String> redirectUris) {
        entity.setRedirectUris(redirectUris);
    }

    @Override
    public void addRedirectUri(String redirectUri) {
        entity.getRedirectUris().add(redirectUri);
    }

    @Override
    public void removeRedirectUri(String redirectUri) {
        entity.getRedirectUris().remove(redirectUri);
    }

    @Override
    public String getClientAuthenticatorType() {
        return entity.getClientAuthenticatorType();
    }

    @Override
    public void setClientAuthenticatorType(String clientAuthenticatorType) {
        entity.setClientAuthenticatorType(clientAuthenticatorType);
    }

    @Override
    public String getSecret() {
        return entity.getSecret();
    }

    @Override
    public void setSecret(String secret) {
        entity.setSecret(secret);
    }

    @Override
    public String getRegistrationToken() {
        return entity.getRegistrationToken();
    }

    @Override
    public void setRegistrationToken(String registrationToken) {
        entity.setRegistrationToken(registrationToken);
    }

    @Override
    public boolean validateSecret(String secret) {
        return MessageDigest.isEqual(secret.getBytes(), entity.getSecret().getBytes());
    }

    @Override
    public int getNotBefore() {
        return entity.getNotBefore();
    }

    @Override
    public void setNotBefore(int notBefore) {
        entity.setNotBefore(notBefore);
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
        return getEntity().getScopeMapping().stream()
                .map(Role::getId)
                .map(realm::getRoleById)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    @Override
    public void addScopeMapping(RoleModel role) {
        Role roleEntity = roleAdapter.toRoleEntity(role);
        getEntity().getScopeMapping().add(roleEntity);
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        getEntity().getScopeMapping().remove(roleAdapter.toRoleEntity(role));
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
    public void setAuthenticationFlowBindingOverride(String name, String value) {
        entity.getAuthFlowBindings().put(name, value);

    }

    @Override
    public void removeAuthenticationFlowBindingOverride(String name) {
        entity.getAuthFlowBindings().remove(name);
    }

    @Override
    public String getAuthenticationFlowBindingOverride(String name) {
        return entity.getAuthFlowBindings().get(name);
    }

    @Override
    public Map<String, String> getAuthenticationFlowBindingOverrides() {
        return new HashMap<>(entity.getAuthFlowBindings());
    }

    @Override
    public void setAttribute(String name, String value) {
        for (ClientAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                attr.setValue(value);
                return;
            }
        }

        ClientAttribute attr = new ClientAttribute();
        attr.setName(name);
        attr.setValue(value);
        attr.setClient(entity);
        clientAttributeRepository.save(attr);
        entity.getAttributes().add(attr);
    }

    @Override
    public void removeAttribute(String name) {
        Iterator<ClientAttribute> it = entity.getAttributes().iterator();
        while (it.hasNext()) {
            ClientAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                clientAttributeRepository.delete(attr);
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
        for (ClientAttribute attr : entity.getAttributes()) {
            attrs.put(attr.getName(), attr.getValue());
        }
        return attrs;
    }

    @Override
    public void addClientScope(ClientScopeModel clientScope, boolean defaultScope) {
        if (getClientScopes(defaultScope, false).containsKey(clientScope.getName())) return;

        ClientScopeClientMapping entity = new ClientScopeClientMapping();
        entity.setClientScope(clientScopeAdapter.toClientScopeEntity(clientScope));
        entity.setClient(getEntity());
        entity.setDefaultScope(defaultScope);
        clientScopeClientMappingRepository.save(entity);
    }

    @Override
    public void removeClientScope(ClientScopeModel clientScope) {
        clientScopeClientMappingRepository.deleteClientScopeClientMapping(
                getEntity(),
                clientScopeAdapter.toClientScopeEntity(clientScope)
        );
    }

    @Override
    public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope, boolean filterByProtocol) {
        List<String> ids = clientScopeClientMappingRepository.clientScopeClientMappingIdsByClient(getEntity(), defaultScope);

        // Defaults to openid-connect
        String clientProtocol = getProtocol() == null ? OIDCLoginProtocol.LOGIN_PROTOCOL : getProtocol();

        Map<String, ClientScopeModel> clientScopes = new HashMap<>();
        for (String clientScopeId : ids) {
            ClientScopeModel clientScope = realm.getClientScopeById(clientScopeId);
            if (clientScope == null) continue;
            if (!filterByProtocol || clientScope.getProtocol().equals(clientProtocol)) {
                clientScopes.put(clientScope.getName(), clientScope);
            }
        }
        return clientScopes;
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
        entity.setClient(this.entity);
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
    public void updateClient() {
        applicationEventPublisher.publishEvent(new ClientUpdatedEvent(this));
    }

    @Override
    public String getClientId() {
        return entity.getClientId();
    }

    @Override
    public void setClientId(String clientId) {
        entity.setClientId(clientId);
    }

    @Override
    public boolean isSurrogateAuthRequired() {
        return entity.isSurrogateAuthRequired();
    }

    @Override
    public void setSurrogateAuthRequired(boolean surrogateAuthRequired) {
        entity.setSurrogateAuthRequired(surrogateAuthRequired);
    }

    @Override
    public String getManagementUrl() {
        return entity.getManagementUrl();
    }

    @Override
    public void setManagementUrl(String url) {
        entity.setManagementUrl(url);
    }

    @Override
    public String getRootUrl() {
        return entity.getRootUrl();
    }

    @Override
    public void setRootUrl(String url) {
        entity.setRootUrl(url);
    }

    @Override
    public String getBaseUrl() {
        return entity.getBaseUrl();
    }

    @Override
    public void setBaseUrl(String url) {
        entity.setBaseUrl(url);
    }

    @Override
    public boolean isBearerOnly() {
        return entity.isBearerOnly();
    }

    @Override
    public void setBearerOnly(boolean only) {
        entity.setBearerOnly(only);
    }

    @Override
    public boolean isConsentRequired() {
        return entity.isConsentRequired();
    }

    @Override
    public void setConsentRequired(boolean consentRequired) {
        entity.setConsentRequired(consentRequired);
    }

    @Override
    public boolean isStandardFlowEnabled() {
        return entity.isStandardFlowEnabled();
    }

    @Override
    public void setStandardFlowEnabled(boolean standardFlowEnabled) {
        entity.setStandardFlowEnabled(standardFlowEnabled);
    }

    @Override
    public boolean isImplicitFlowEnabled() {
        return entity.isImplicitFlowEnabled();
    }

    @Override
    public void setImplicitFlowEnabled(boolean implicitFlowEnabled) {
        entity.setImplicitFlowEnabled(implicitFlowEnabled);
    }

    @Override
    public boolean isDirectAccessGrantsEnabled() {
        return entity.isDirectAccessGrantsEnabled();
    }

    @Override
    public void setDirectAccessGrantsEnabled(boolean directAccessGrantsEnabled) {
        entity.setDirectAccessGrantsEnabled(directAccessGrantsEnabled);
    }

    @Override
    public boolean isServiceAccountsEnabled() {
        return entity.isServiceAccountsEnabled();
    }

    @Override
    public void setServiceAccountsEnabled(boolean serviceAccountsEnabled) {
        entity.setServiceAccountsEnabled(serviceAccountsEnabled);
    }

    @Override
    public RoleModel getRole(String name) {
        return realmProvider.getClientRole(realm, this, name);
    }

    @Override
    public RoleModel addRole(String name) {
        return realmProvider.addClientRole(realm, this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return realmProvider.addClientRole(realm, this, id, name);
    }

    @Override
    public boolean removeRole(RoleModel roleModel) {
        return realmProvider.removeRole(realm, roleModel);
    }

    @Override
    public Set<RoleModel> getRoles() {
        return realmProvider.getClientRoles(realm, this);
    }

    @Override
    public Set<RoleModel> getRoles(Integer first, Integer max) {
        return realmProvider.getClientRoles(realm, this, first, max);
    }

    @Override
    public Set<RoleModel> searchForRoles(String search, Integer first, Integer max) {
        return realmProvider.searchForClientRoles(realm, this, search, first, max);
    }

    @Override
    public boolean hasScope(RoleModel role) {
        if (isFullScopeAllowed()) return true;
        Set<RoleModel> roles = getScopeMappings();
        if (roles.contains(role)) return true;

        for (RoleModel mapping : roles) {
            if (mapping.hasRole(role)) return true;
        }
        roles = getRoles();
        if (roles.contains(role)) return true;

        for (RoleModel mapping : roles) {
            if (mapping.hasRole(role)) return true;
        }
        return false;
    }

    @Override
    public List<String> getDefaultRoles() {
        Collection<Role> entities = entity.getDefaultRoles();
        List<String> roles = new ArrayList<>();
        if (entities == null) return roles;
        for (Role entity : entities) {
            roles.add(entity.getName());
        }
        return roles;
    }

    @Override
    public void addDefaultRole(String name) {
        RoleModel role = getRole(name);
        if (role == null) {
            role = addRole(name);
        }
        Collection<Role> entities = entity.getDefaultRoles();
        for (Role entity : entities) {
            if (entity.getId().equals(role.getId())) {
                return;
            }
        }
        Role roleEntity = roleAdapter.toRoleEntity(role);
        entities.add(roleEntity);
    }

    @Override
    public void updateDefaultRoles(String... defaultRoles) {
        Collection<Role> entities = entity.getDefaultRoles();
        Set<String> already = new HashSet<>();
        List<Role> remove = new ArrayList<>();
        for (Role rel : entities) {
            if (!contains(rel.getName(), defaultRoles)) {
                remove.add(rel);
            } else {
                already.add(rel.getName());
            }
        }
        for (Role entity : remove) {
            entities.remove(entity);
        }
        roleRepository.deleteAll(remove);
        for (String roleName : defaultRoles) {
            if (!already.contains(roleName)) {
                addDefaultRole(roleName);
            }
        }
    }

    @Override
    public void removeDefaultRoles(String... defaultRoles) {
        Collection<Role> entities = entity.getDefaultRoles();
        List<Role> remove = new ArrayList<>();
        for (Role rel : entities) {
            if (contains(rel.getName(), defaultRoles)) {
                remove.add(rel);
            }
        }
        for (Role entity : remove) {
            entities.remove(entity);
        }
        roleRepository.deleteAll(remove);
    }

    @Override
    public int getNodeReRegistrationTimeout() {
        return entity.getNodeReRegistrationTimeout();
    }

    @Override
    public void setNodeReRegistrationTimeout(int timeout) {
        entity.setNodeReRegistrationTimeout(timeout);
    }

    @Override
    public Map<String, Integer> getRegisteredNodes() {
        return entity.getRegisteredNodes();
    }

    @Override
    public void registerNode(String nodeHost, int registrationTime) {
        Map<String, Integer> currentNodes = getRegisteredNodes();
        currentNodes.put(nodeHost, registrationTime);
    }

    @Override
    public void unregisterNode(String nodeHost) {
        Map<String, Integer> currentNodes = getRegisteredNodes();
        currentNodes.remove(nodeHost);
        clientRepository.save(entity);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientModel)) return false;

        ClientModel that = (ClientModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    public String toString() {
        return getClientId();
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}
