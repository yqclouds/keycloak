package com.hsbc.unified.iam.core.service;

import com.hsbc.unified.iam.core.entity.SslRequired;
import com.hsbc.unified.iam.core.entity.Realm;

import java.util.Map;

public interface RealmService {
    String getId(Realm entity);

    String getName(Realm entity);

    void setName(Realm entity, String name);

    String getDisplayName(Realm entity);

    void setDisplayName(Realm entity, String displayName);

    String getDisplayNameHtml(Realm entity);

    void setDisplayNameHtml(Realm entity, String displayNameHtml);

    boolean isEnabled(Realm entity);

    void setEnabled(Realm entity, boolean enabled);

    SslRequired getSslRequired(Realm entity);

    void setAttribute(Realm entity, String name, String value);

    void setAttribute(Realm entity, String name, Boolean value);

    void setAttribute(Realm entity, String name, Integer value);

    void setAttribute(Realm entity, String name, Long value);

    void removeAttribute(Realm entity, String name);

    String getAttribute(Realm entity, String name);

    Integer getAttribute(Realm entity, String name, Integer defaultValue);

    Long getAttribute(Realm entity, String name, Long defaultValue);

    Boolean getAttribute(Realm entity, String name, Boolean defaultValue);

    Map<String, String> getAttributes(Realm entity);
}
