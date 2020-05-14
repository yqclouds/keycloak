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

package com.hsbc.unified.iam.entity;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Entity
@Table(name = "USER_CONSENT", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"USER_ID", "CLIENT_ID"})
})
@NamedQueries({
        @NamedQuery(name = "userConsentByUserAndClient", query = "select consent from UserConsent consent where consent.user.id = :userId and consent.clientId = :clientId"),
        @NamedQuery(name = "userConsentByUserAndExternalClient", query = "select consent from UserConsent consent where consent.user.id = :userId and consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId"),
        @NamedQuery(name = "userConsentsByUser", query = "select consent from UserConsent consent where consent.user.id = :userId"),
        @NamedQuery(name = "deleteUserConsentsByRealm", query = "delete from UserConsent consent where consent.user IN (select user from User user where user.realmId = :realmId)"),
        @NamedQuery(name = "deleteUserConsentsByRealmAndLink", query = "delete from UserConsent consent where consent.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name = "deleteUserConsentsByUser", query = "delete from UserConsent consent where consent.user = :user"),
        @NamedQuery(name = "deleteUserConsentsByClient", query = "delete from UserConsent consent where consent.clientId = :clientId"),
        @NamedQuery(name = "deleteUserConsentsByExternalClient", query = "delete from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId"),
        @NamedQuery(name = "deleteUserConsentsByClientStorageProvider", query = "delete from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider"),
})
public class UserConsent {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    protected User user;

    @Column(name = "CLIENT_ID")
    protected String clientId;

    @Column(name = "CLIENT_STORAGE_PROVIDER")
    protected String clientStorageProvider;

    @Column(name = "EXTERNAL_CLIENT_ID")
    protected String externalClientId;

    @OneToMany(cascade = {CascadeType.REMOVE}, orphanRemoval = true, mappedBy = "userConsent")
    Collection<UserConsentClientScope> grantedClientScopes = new ArrayList<>();

    @Column(name = "CREATED_DATE")
    private Long createdDate;

    @Column(name = "LAST_UPDATED_DATE")
    private Long lastUpdatedDate;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Collection<UserConsentClientScope> getGrantedClientScopes() {
        return grantedClientScopes;
    }

    public void setGrantedClientScopes(Collection<UserConsentClientScope> grantedClientScopes) {
        this.grantedClientScopes = grantedClientScopes;
    }

    public Long getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Long createdDate) {
        this.createdDate = createdDate;
    }

    public Long getLastUpdatedDate() {
        return lastUpdatedDate;
    }

    public void setLastUpdatedDate(Long lastUpdatedDate) {
        this.lastUpdatedDate = lastUpdatedDate;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientStorageProvider() {
        return clientStorageProvider;
    }

    public void setClientStorageProvider(String clientStorageProvider) {
        this.clientStorageProvider = clientStorageProvider;
    }

    public String getExternalClientId() {
        return externalClientId;
    }

    public void setExternalClientId(String externalClientId) {
        this.externalClientId = externalClientId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserConsent)) return false;

        UserConsent that = (UserConsent) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
