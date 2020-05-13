package com.hsbc.unified.iam.core.service.impl;

import com.hsbc.unified.iam.core.entity.Client;
import com.hsbc.unified.iam.core.entity.Realm;
import com.hsbc.unified.iam.core.entity.Role;
import com.hsbc.unified.iam.core.repository.RealmRepository;
import com.hsbc.unified.iam.core.repository.RoleRepository;
import com.hsbc.unified.iam.core.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class RoleServiceImpl implements RoleService {
    @Autowired
    private RealmRepository realmRepository;
    @Autowired
    private RoleRepository roleRepository;

    @Override
    @Transactional
    public Role createRole(String id, String name, Realm realm) {
        Role entity = new Role();
        entity.setId(id);
        entity.setName(name);
        Realm ref = realmRepository.getOne(realm.getId());
        entity.setRealm(ref);
        entity.setRealmId(realm.getId());

        return roleRepository.saveAndFlush(entity);
    }

    @Override
    @Transactional
    public Role createRole(String id, String name, Client client, String realm) {
        Role entity = new Role();
        entity.setId(id);
        entity.setName(name);
        entity.setClient(client);
        entity.setClientRole(true);
        entity.setRealmId(realm);

        return roleRepository.saveAndFlush(entity);
    }
}
