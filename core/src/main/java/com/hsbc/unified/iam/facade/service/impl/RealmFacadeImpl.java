package com.hsbc.unified.iam.facade.service.impl;

import com.hsbc.unified.iam.entity.Realm;
import com.hsbc.unified.iam.entity.RealmRequiredCredential;
import com.hsbc.unified.iam.entity.Role;
import com.hsbc.unified.iam.facade.service.RealmFacade;
import com.hsbc.unified.iam.service.RealmService;
import org.apache.commons.collections4.CollectionUtils;
import org.keycloak.models.RequiredCredentialModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.*;

@Component
public class RealmFacadeImpl implements RealmFacade {
    @Autowired
    private RealmService realmService;

    @Override
    public void addRequiredCredential(Realm realm, String type) {
        RealmRequiredCredential entity = newRealmRequiredCredential(type);

        this.realmService.createRequiredCredential(realm, entity);
    }

    private RealmRequiredCredential newRealmRequiredCredential(String type) {
        RequiredCredentialModel model = RequiredCredentialModel.BUILT_IN.get(type);
        Assert.notNull(model, "Unknown credential type " + type);

        RealmRequiredCredential entity = new RealmRequiredCredential();
        entity.setInput(model.isInput());
        entity.setSecret(model.isSecret());
        entity.setType(model.getType());
        entity.setFormLabel(model.getFormLabel());

        return entity;
    }

    @Override
    public void updateRequiredCredentials(Realm realm, Set<String> credentials) {
        Collection<RealmRequiredCredential> relationships = realm.getRequiredCredentials();

        Set<String> already = new HashSet<>();

        List<RealmRequiredCredential> added = new ArrayList<>();
        List<RealmRequiredCredential> removed = new ArrayList<>();

        for (RealmRequiredCredential rel : relationships) {
            if (!credentials.contains(rel.getType())) {
                removed.add(rel);
            } else {
                already.add(rel.getType());
            }
        }

        for (String cred : credentials) {
            if (!already.contains(cred)) {
                added.add(newRealmRequiredCredential(cred));
            }
        }

        this.realmService.updateRequiredCredentials(realm, added, removed);
    }

    @Override
    public List<RequiredCredentialModel> getRequiredCredentials(Realm realm) {
        Collection<RealmRequiredCredential> entities = realm.getRequiredCredentials();

        List<RequiredCredentialModel> results = new LinkedList<>();
        for (RealmRequiredCredential entity : entities) {
            RequiredCredentialModel model = new RequiredCredentialModel();
            model.setFormLabel(entity.getFormLabel());
            model.setType(entity.getType());
            model.setSecret(entity.isSecret());
            model.setInput(entity.isInput());
            results.add(model);
        }

        return Collections.unmodifiableList(results);
    }

    @Override
    public List<String> getDefaultRoles(Realm realm) {
        Collection<Role> entities = realm.getDefaultRoles();
        if (CollectionUtils.isEmpty(entities)) {
            return Collections.emptyList();
        }

        List<String> roles = new LinkedList<>();
        for (Role entity : entities) {
            roles.add(entity.getName());
        }

        return Collections.unmodifiableList(roles);
    }
}
