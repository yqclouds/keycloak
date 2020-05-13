package com.hsbc.unified.iam.core.service.impl;

import com.hsbc.unified.iam.core.entity.SslRequired;
import com.hsbc.unified.iam.core.entity.Realm;
import com.hsbc.unified.iam.core.entity.RealmAttribute;
import com.hsbc.unified.iam.core.repository.RealmAttributeRepository;
import com.hsbc.unified.iam.core.repository.RealmRepository;
import com.hsbc.unified.iam.core.service.RealmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

@Service
@Transactional(readOnly = true)
public class RealmServiceImpl implements RealmService {
    @Autowired
    private RealmRepository realmRepository;
    @Autowired
    private RealmAttributeRepository realmAttributeRepository;

    @Override
    public String getId(Realm entity) {
        return entity.getId();
    }

    @Override
    public String getName(Realm entity) {
        return entity.getName();
    }

    @Override
    @Transactional
    public void setName(Realm entity, String name) {
        entity.setName(name);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getDisplayName(Realm entity) {
        return getAttribute(entity, RealmAttribute.DISPLAY_NAME);
    }

    @Override
    @Transactional
    public void setDisplayName(Realm entity, String displayName) {
        setAttribute(entity, RealmAttribute.DISPLAY_NAME, displayName);
    }

    @Override
    public String getDisplayNameHtml(Realm entity) {
        return getAttribute(entity, RealmAttribute.DISPLAY_NAME_HTML);
    }

    @Override
    @Transactional
    public void setDisplayNameHtml(Realm entity, String displayNameHtml) {
        setAttribute(entity, RealmAttribute.DISPLAY_NAME_HTML, displayNameHtml);
    }

    @Override
    public boolean isEnabled(Realm entity) {
        return entity.isEnabled();
    }

    @Override
    @Transactional
    public void setEnabled(Realm entity, boolean enabled) {
        entity.setEnabled(enabled);
        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public SslRequired getSslRequired(Realm entity) {
        return entity.getSslRequired() != null ? SslRequired.valueOf(entity.getSslRequired()) : null;
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, String value) {
        for (RealmAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                attr.setValue(value);
                return;
            }
        }

        RealmAttribute attr = new RealmAttribute();
        attr.setName(name);
        attr.setValue(value);
        attr.setRealm(entity);
        this.realmAttributeRepository.saveAndFlush(attr);

        entity.getAttributes().add(attr);

        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Boolean value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Integer value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void setAttribute(Realm entity, String name, Long value) {
        setAttribute(entity, name, Objects.toString(value));
    }

    @Override
    @Transactional
    public void removeAttribute(Realm entity, String name) {
        Iterator<RealmAttribute> it = entity.getAttributes().iterator();
        while (it.hasNext()) {
            RealmAttribute attr = it.next();
            if (attr.getName().equals(name)) {
                it.remove();
                this.realmAttributeRepository.delete(attr);
            }
        }

        this.realmRepository.saveAndFlush(entity);
    }

    @Override
    public String getAttribute(Realm entity, String name) {
        for (RealmAttribute attr : entity.getAttributes()) {
            if (attr.getName().equals(name)) {
                return attr.getValue();
            }
        }

        return null;
    }

    @Override
    public Integer getAttribute(Realm entity, String name, Integer defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Integer.parseInt(v) : defaultValue;
    }

    @Override
    public Long getAttribute(Realm entity, String name, Long defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Long.parseLong(v) : defaultValue;
    }

    @Override
    public Boolean getAttribute(Realm entity, String name, Boolean defaultValue) {
        String v = getAttribute(entity, name);
        return v != null ? Boolean.parseBoolean(v) : defaultValue;
    }

    @Override
    public Map<String, String> getAttributes(Realm entity) {
        // should always return a copy
        Map<String, String> results = new HashMap<>();
        for (RealmAttribute attr : entity.getAttributes()) {
            results.put(attr.getName(), attr.getValue());
        }
        return results;
    }
}
