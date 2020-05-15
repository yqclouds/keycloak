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

package com.hsbc.unified.iam.legacy.adapter.impl;

import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.entity.*;
import com.hsbc.unified.iam.entity.events.ClientCreationEvent;
import com.hsbc.unified.iam.entity.events.ClientRemovedEvent;
import com.hsbc.unified.iam.entity.events.RealmCreationEvent;
import com.hsbc.unified.iam.entity.events.RoleRemovedEvent;
import com.hsbc.unified.iam.repository.*;
import com.hsbc.unified.iam.service.ClientService;
import com.hsbc.unified.iam.service.GroupService;
import com.hsbc.unified.iam.service.RealmService;
import com.hsbc.unified.iam.service.RoleService;
import org.keycloak.models.*;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.ClientScopeAdapter;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.*;
import java.util.stream.Collectors;


/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JpaRealmProvider implements RealmProvider, ApplicationEventPublisherAware {
    protected static final Logger LOG = LoggerFactory.getLogger(JpaRealmProvider.class);

    private ApplicationEventPublisher applicationEventPublisher;

    private final KeycloakSession session;
    protected EntityManager em;

    @Autowired
    private RealmService realmService;
    @Autowired
    private ClientService clientService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private GroupService groupService;
    @Autowired
    private RealmRepository realmRepository;
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private GroupRoleMappingRepository groupRoleMappingRepository;
    @Autowired
    private DefaultClientScopeRealmMappingRepository defaultClientScopeRealmMappingRepository;
    @Autowired
    private ClientInitialAccessRepository clientInitialAccessRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ClientScopeRoleMappingRepository clientScopeRoleMappingRepository;
    @Autowired
    private ClientScopeClientMappingRepository clientScopeClientMappingRepository;

    public JpaRealmProvider(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    @Override
    public RealmModel createRealm(String name) {
        return createRealm(KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RealmModel createRealm(String id, String name) {
        Realm realm = this.realmService.createRealm(id, name);
        applicationEventPublisher.publishEvent(new RealmCreationEvent(realm));
        return new RealmAdapter(session, em, realm);
    }

    @Override
    public RealmModel getRealm(String id) {
        return new RealmAdapter(session, em, this.realmService.getRealm(id));
    }

    @Override
    public List<RealmModel> getRealmsWithProviderType(Class<?> providerType) {
        return getRealms(this.realmService.getRealmsWithProviderType(providerType));
    }

    @Override
    public List<RealmModel> getRealms() {
        return getRealms(this.realmService.getAllRealmIds());
    }

    private List<RealmModel> getRealms(List<String> entities) {
        List<RealmModel> realms = new ArrayList<>();
        for (String id : entities) {
            RealmModel realm = session.realms().getRealm(id);
            if (realm != null) realms.add(realm);
            em.flush();
        }
        return realms;
    }

    @Override
    public RealmModel getRealmByName(String name) {
        List<String> entities = this.realmService.getRealmIdByName(name);
        if (entities.isEmpty()) {
            return null;
        }

        if (entities.size() > 1) {
            throw new IllegalStateException("Should not be more than one realm with same name");
        }

        return session.realms().getRealm(entities.get(0));
    }

    @Override
    public boolean removeRealm(String id) {
        Realm realm = this.realmService.getRealm(id);
        if (realm == null) {
            return false;
        }
        final RealmAdapter adapter = new RealmAdapter(session, em, realm);
        session.users().preRemove(adapter);

        realmService.removeDefaultGroups(realm);
        groupRoleMappingRepository.deleteGroupRoleMappingsByRealm(realm);
        List<String> clients = clientRepository.getClientIdsByRealm(realm.getId());
        for (String client : clients) {
            // No need to go through cache. Clients were already invalidated
            removeClient(client, adapter);
        }
        defaultClientScopeRealmMappingRepository.deleteDefaultClientScopeRealmMappingByRealm(realm);
        for (ClientScope a : new LinkedList<>(realm.getClientScopes())) {
            adapter.removeClientScope(a.getId());
        }

        for (RoleModel role : adapter.getRoles()) {
            // No need to go through cache. Roles were already invalidated
            removeRole(adapter, role);
        }

        for (GroupModel group : adapter.getGroups()) {
            session.realms().removeGroup(adapter, group);
        }

        clientInitialAccessRepository.removeClientInitialAccessByRealm(realm);
        realmRepository.delete(realm);
        applicationEventPublisher.publishEvent(new RealmCreationEvent(realm));

        return true;
    }

    @Override
    public void close() {
    }

    @Override
    public RoleModel addRealmRole(RealmModel realm, String name) {
        return addRealmRole(realm, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addRealmRole(RealmModel realm, String id, String name) {
        if (getRealmRole(realm, name) != null) {
            throw new ModelDuplicateException();
        }

        Realm ref = realmRepository.getOne(realm.getId());
        Role entity = roleService.createRole(id, name, ref);
        return new RoleAdapter(session, realm, em, entity);
    }

    @Override
    public RoleModel getRealmRole(RealmModel realm, String name) {
        TypedQuery<String> query = em.createNamedQuery("getRealmRoleIdByName", String.class);
        query.setParameter("name", name);
        query.setParameter("realm", realm.getId());
        List<String> roles = roleRepository.getRealmRoleIdByName(name, realm.getId());
        if (roles.isEmpty()) return null;
        return session.realms().getRoleById(roles.get(0), realm);
    }

    @Override
    public RoleModel addClientRole(RealmModel realm, ClientModel client, String name) {
        return addClientRole(realm, client, KeycloakModelUtils.generateId(), name);
    }

    @Override
    public RoleModel addClientRole(RealmModel realm, ClientModel client, String id, String name) {
        if (getClientRole(realm, client, name) != null) {
            throw new ModelDuplicateException();
        }

        Client clientEntity = clientRepository.getOne(client.getId());
        Role roleEntity = roleService.createRole(id, name, clientEntity, realm.getId());
        return new RoleAdapter(session, realm, em, roleEntity);
    }

    @Override
    public Set<RoleModel> getRealmRoles(RealmModel realm) {
        List<String> roles = roleRepository.getRealmRoleIds(realm.getId());
        if (roles.isEmpty()) return Collections.EMPTY_SET;
        Set<RoleModel> list = new HashSet<>();
        for (String id : roles) {
            list.add(session.realms().getRoleById(id, realm));
        }
        return Collections.unmodifiableSet(list);
    }

    @Override
    public RoleModel getClientRole(RealmModel realm, ClientModel client, String name) {
        List<String> roles = roleRepository.getClientRoleIdByName(name, client.getId());
        if (roles.isEmpty()) return null;
        return session.realms().getRoleById(roles.get(0), realm);
    }


    @Override
    public Set<RoleModel> getClientRoles(RealmModel realm, ClientModel client) {
        Set<RoleModel> list = new HashSet<>();

        List<String> roles = roleRepository.getClientRoleIds(client.getId());
        for (String id : roles) {
            list.add(session.realms().getRoleById(id, realm));
        }

        return list;
    }

    @Override
    public Set<RoleModel> getRealmRoles(RealmModel realm, Integer first, Integer max) {
        List<Role> roles = roleRepository.getRealmRoles(realm.getId());
        return getRoles(roles, realm);
    }

    @Override
    public Set<RoleModel> getClientRoles(RealmModel realm, ClientModel client, Integer first, Integer max) {
        List<Role> roles = roleRepository.getClientRoles(client.getId());
        return getRoles(roles, realm);
    }

    protected Set<RoleModel> getRoles(List<Role> results, RealmModel realm) {
        return results.stream()
                .map(role -> new RoleAdapter(session, realm, em, role))
                .collect(Collectors.collectingAndThen(
                        Collectors.toCollection(LinkedHashSet::new), Collections::unmodifiableSet));
    }

    @Override
    public Set<RoleModel> searchForClientRoles(RealmModel realm, ClientModel client, String search, Integer first, Integer max) {
        List<Role> roles = roleRepository.searchForClientRoles(client.getId(), search);
        return searchForRoles(roles, realm);
    }

    @Override
    public Set<RoleModel> searchForRoles(RealmModel realm, String search, Integer first, Integer max) {
        List<Role> roles = roleRepository.searchForRealmRoles(realm.getId(), "%" + search.trim().toLowerCase() + "%");
        return searchForRoles(roles, realm);
    }

    private Set<RoleModel> searchForRoles(List<Role> results, RealmModel realm) {
        return results.stream()
                .map(role -> new RoleAdapter(session, realm, em, role))
                .collect(Collectors.collectingAndThen(
                        Collectors.toSet(), Collections::unmodifiableSet));
    }

    @Override
    public boolean removeRole(RealmModel realm, RoleModel role) {
        session.users().preRemove(realm, role);
        RoleContainerModel container = role.getContainer();
        if (container.getDefaultRoles().contains(role.getName())) {
            container.removeDefaultRoles(role.getName());
        }
        Role roleEntity = roleRepository.getOne(role.getId());
        roleRepository.deleteCompositeRoles(roleEntity);

        realm.getClients().forEach(c -> c.deleteScopeMapping(role));
        clientScopeRoleMappingRepository.deleteClientScopeRoleMappingByRole(roleEntity);
        groupRoleMappingRepository.deleteGroupRoleMappingsByRole(roleEntity.getId());
        roleRepository.delete(roleEntity);

        applicationEventPublisher.publishEvent(new RoleRemovedEvent(roleEntity));

        return true;
    }

    @Override
    public RoleModel getRoleById(String id, RealmModel realm) {
        Optional<Role> optional = roleRepository.findById(id);
        if (!optional.isPresent()) return null;

        Role entity = optional.get();
        if (!realm.getId().equals(entity.getRealmId())) return null;
        return new RoleAdapter(session, realm, em, entity);
    }

    @Override
    public GroupModel getGroupById(String id, RealmModel realm) {
        Optional<Group> optional = groupRepository.findById(id);
        if (!optional.isPresent()) return null;

        Group group = optional.get();
        if (!group.getRealm().getId().equals(realm.getId())) return null;
        return new GroupAdapter(realm, em, group);
    }

    @Override
    public void moveGroup(RealmModel realm, GroupModel group, GroupModel toParent) {
        if (toParent != null && group.getId().equals(toParent.getId())) {
            return;
        }
        if (group.getParentId() != null) {
            group.getParent().removeChild(group);
        }
        group.setParent(toParent);
        if (toParent != null) toParent.addChild(group);
        else session.realms().addTopLevelGroup(realm, group);
    }

    @Override
    public List<GroupModel> getGroups(RealmModel realm) {
        Realm ref = realmRepository.getOne(realm.getId());
        return ref.getGroups().stream()
                .map(g -> session.realms().getGroupById(g.getId(), realm))
                .sorted(Comparator.comparing(GroupModel::getName))
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(), Collections::unmodifiableList));
    }

    @Override
    public Long getGroupsCount(RealmModel realm, Boolean onlyTopGroups) {
        if (Objects.equals(onlyTopGroups, Boolean.TRUE)) {
            return groupRepository.getTopLevelGroupCount(realm.getId(), Group.TOP_PARENT_ID);
        }

        return groupRepository.getGroupCount(realm.getId());
    }

    @Override
    public Long getClientsCount(RealmModel realm) {
        return clientRepository.getRealmClientsCount(realm.getId());
    }

    @Override
    public Long getGroupsCountByNameContaining(RealmModel realm, String search) {
        return (long) searchForGroupByName(realm, search, null, null).size();
    }

    @Override
    public List<GroupModel> getGroupsByRole(RealmModel realm, RoleModel role, int firstResult, int maxResults) {
        List<Group> results = groupRoleMappingRepository.findGroupsInRole(role.getId());
        return results.stream()
                .map(g -> new GroupAdapter(realm, em, g))
                .sorted(Comparator.comparing(GroupModel::getName))
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(), Collections::unmodifiableList));
    }

    @Override
    public List<GroupModel> getTopLevelGroups(RealmModel realm) {
        Realm ref = realmRepository.getOne(realm.getId());
        return ref.getGroups().stream()
                .filter(g -> Group.TOP_PARENT_ID.equals(g.getParentId()))
                .map(g -> session.realms().getGroupById(g.getId(), realm))
                .sorted(Comparator.comparing(GroupModel::getName))
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(), Collections::unmodifiableList));
    }

    @Override
    public List<GroupModel> getTopLevelGroups(RealmModel realm, Integer first, Integer max) {
        List<String> groupIds = groupRepository.getTopLevelGroupIds(realm.getId(), Group.TOP_PARENT_ID);
        List<GroupModel> list = new ArrayList<>();
        if (Objects.nonNull(groupIds) && !groupIds.isEmpty()) {
            for (String id : groupIds) {
                GroupModel group = getGroupById(id, realm);
                list.add(group);
            }
        }
        // no need to sort, it's sorted at database level
        return Collections.unmodifiableList(list);
    }

    @Override
    public boolean removeGroup(RealmModel realm, GroupModel group) {
        if (group == null) {
            return false;
        }
        session.users().preRemove(realm, group);

        realm.removeDefaultGroup(group);
        for (GroupModel subGroup : group.getSubGroups()) {
            session.realms().removeGroup(realm, subGroup);
        }
        Group groupEntity = groupRepository.getOne(group.getId());
        if ((groupEntity == null) || (!groupEntity.getRealm().getId().equals(realm.getId()))) {
            return false;
        }
        groupRoleMappingRepository.deleteGroupRoleMappingsByGroup(groupEntity);

        Realm realmEntity = realmRepository.getOne(realm.getId());
        realmEntity.getGroups().remove(groupEntity);
        groupRepository.delete(groupEntity);

        return true;
    }

    @Override
    public GroupModel createGroup(RealmModel realm, String id, String name, GroupModel toParent) {
        if (id == null) {
            id = KeycloakModelUtils.generateId();
        } else if (Group.TOP_PARENT_ID.equals(id)) {
            // maybe it's impossible but better ensure this doesn't happen
            throw new ModelException("The ID of the new group is equals to the tag used for top level groups");
        }

        Realm realmEntity = realmRepository.getOne(realm.getId());
        Group groupEntity = groupService.createGroup(id, name, realmEntity, toParent == null ? null : toParent.getId());
        realmEntity.getGroups().add(groupEntity);
        realmRepository.saveAndFlush(realmEntity);

        return new GroupAdapter(realm, em, groupEntity);
    }

    @Override
    public void addTopLevelGroup(RealmModel realm, GroupModel subGroup) {
        subGroup.setParent(null);
    }

    @Override
    public ClientModel addClient(RealmModel realm, String clientId) {
        return addClient(realm, KeycloakModelUtils.generateId(), clientId);
    }

    @Override
    public ClientModel addClient(RealmModel realm, String id, String clientId) {
        if (clientId == null) {
            clientId = id;
        }
        Realm realmRef = realmRepository.getOne(realm.getId());

        Client entity = clientService.createClient(id, clientId, realmRef);
        applicationEventPublisher.publishEvent(new ClientCreationEvent(entity));

        return new ClientAdapter(realm, em, session, entity);
    }

    @Override
    public List<ClientModel> getClients(RealmModel realm, Integer firstResult, Integer maxResults) {
        List<String> clients = clientRepository.getClientIdsByRealm(realm.getId());
        if (clients.isEmpty()) return Collections.EMPTY_LIST;
        List<ClientModel> list = new LinkedList<>();
        for (String id : clients) {
            ClientModel client = session.realms().getClientById(id, realm);
            if (client != null) list.add(client);
        }
        return Collections.unmodifiableList(list);
    }

    @Override
    public List<ClientModel> getClients(RealmModel realm) {
        return this.getClients(realm, null, null);
    }

    @Override
    public List<ClientModel> getAlwaysDisplayInConsoleClients(RealmModel realm) {
        List<String> clients = clientRepository.getAlwaysDisplayInConsoleClients(realm.getId());
        if (clients.isEmpty()) return Collections.EMPTY_LIST;
        List<ClientModel> list = new LinkedList<>();
        for (String id : clients) {
            ClientModel client = session.realms().getClientById(id, realm);
            if (client != null) list.add(client);
        }
        return Collections.unmodifiableList(list);
    }

    @Override
    public ClientModel getClientById(String id, RealmModel realm) {
        Optional<Client> optional = clientRepository.findById(id);
        // Check if application belongs to this realm
        if (!optional.isPresent() || !realm.getId().equals(optional.get().getRealm().getId())) return null;
        return new ClientAdapter(realm, em, session, optional.get());
    }

    @Override
    public ClientModel getClientByClientId(String clientId, RealmModel realm) {
        List<String> results = clientRepository.findClientIdByClientId(clientId, realm.getId());
        if (results.isEmpty()) return null;
        return session.realms().getClientById(results.get(0), realm);
    }

    @Override
    public List<ClientModel> searchClientsByClientId(String clientId, Integer firstResult, Integer maxResults, RealmModel realm) {
        List<String> results = clientRepository.searchClientsByClientId(clientId, realm.getId());
        if (results.isEmpty()) return Collections.EMPTY_LIST;
        return results.stream().map(id -> session.realms().getClientById(id, realm)).collect(Collectors.toList());
    }

    @Override
    public boolean removeClient(String id, RealmModel realm) {
        final ClientModel client = getClientById(id, realm);
        if (client == null) return false;

        session.users().preRemove(realm, client);

        for (RoleModel role : client.getRoles()) {
            // No need to go through cache. Roles were already invalidated
            removeRole(realm, role);
        }

        Client clientEntity = clientRepository.getOne(client.getId());
        clientScopeClientMappingRepository.deleteClientScopeClientMappingByClient(clientEntity);
        clientRepository.delete(clientEntity);

        applicationEventPublisher.publishEvent(new ClientRemovedEvent(clientEntity));

        return true;
    }

    @Override
    public ClientScopeModel getClientScopeById(String id, RealmModel realm) {
        ClientScope app = em.find(ClientScope.class, id);

        // Check if application belongs to this realm
        if (app == null || !realm.getId().equals(app.getRealm().getId())) return null;
        return new ClientScopeAdapter(realm, em, session, app);
    }

    @Override
    public List<GroupModel> searchForGroupByName(RealmModel realm, String search, Integer first, Integer max) {
        List<String> groups = groupRepository.getGroupIdsByNameContaining(realm.getId(), search);
        if (Objects.isNull(groups)) return Collections.EMPTY_LIST;
        List<GroupModel> list = new ArrayList<>();
        for (String id : groups) {
            GroupModel groupById = session.realms().getGroupById(id, realm);
            while (Objects.nonNull(groupById.getParentId())) {
                groupById = session.realms().getGroupById(groupById.getParentId(), realm);
            }
            if (!list.contains(groupById)) {
                list.add(groupById);
            }
        }
        list.sort(Comparator.comparing(GroupModel::getName));

        return Collections.unmodifiableList(list);
    }

    @Override
    public ClientInitialAccessModel createClientInitialAccessModel(RealmModel realm, int expiration, int count) {
        Realm realmEntity = realmRepository.getOne(realm.getId());
        ClientInitialAccess entity = clientService.createClientInitialAccess(
                KeycloakModelUtils.generateId(), expiration, count, realmEntity
        );

        return entityToModel(entity);
    }

    @Override
    public ClientInitialAccessModel getClientInitialAccessModel(RealmModel realm, String id) {
        Optional<ClientInitialAccess> optional = clientInitialAccessRepository.findById(id);
        return optional.map(this::entityToModel).orElse(null);
    }

    @Override
    public void removeClientInitialAccessModel(RealmModel realm, String id) {
        Optional<ClientInitialAccess> optional = clientInitialAccessRepository.findById(id);
        optional.ifPresent(clientInitialAccess -> clientInitialAccessRepository.delete(clientInitialAccess));
    }

    @Override
    public List<ClientInitialAccessModel> listClientInitialAccess(RealmModel realm) {
        Realm realmEntity = realmRepository.getOne(realm.getId());
        List<ClientInitialAccess> entities = clientInitialAccessRepository.findClientInitialAccessByRealm(realmEntity);
        return entities.stream()
                .map(this::entityToModel)
                .collect(Collectors.toList());
    }

    @Override
    public void removeExpiredClientInitialAccess() {
        clientInitialAccessRepository.removeExpiredClientInitialAccess(Time.currentTime());
    }

    @Override
    public void decreaseRemainingCount(RealmModel realm, ClientInitialAccessModel clientInitialAccess) {
        clientInitialAccessRepository.decreaseClientInitialAccessRemainingCount(clientInitialAccess.getId());
    }

    private ClientInitialAccessModel entityToModel(ClientInitialAccess entity) {
        ClientInitialAccessModel model = new ClientInitialAccessModel();
        model.setId(entity.getId());
        model.setCount(entity.getCount());
        model.setRemainingCount(entity.getRemainingCount());
        model.setExpiration(entity.getExpiration());
        model.setTimestamp(entity.getTimestamp());
        return model;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}
