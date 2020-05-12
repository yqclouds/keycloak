/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.core.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@NamedQueries({
        @NamedQuery(name = "deleteUserConsentClientScopesByRealm", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user IN (select user from User user where user.realmId = :realmId))"),
        @NamedQuery(name = "deleteUserConsentClientScopesByRealmAndLink", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link))"),
        @NamedQuery(name = "deleteUserConsentClientScopesByUser", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.user = :user)"),
        @NamedQuery(name = "deleteUserConsentClientScopesByClientScope", query = "delete from UserConsentClientScope grantedScope where grantedScope.scopeId = :scopeId"),
        @NamedQuery(name = "deleteUserConsentClientScopesByClient", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientId = :clientId)"),
        @NamedQuery(name = "deleteUserConsentClientScopesByExternalClient", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider and consent.externalClientId = :externalClientId)"),
        @NamedQuery(name = "deleteUserConsentClientScopesByClientStorageProvider", query = "delete from UserConsentClientScope grantedScope where grantedScope.userConsent IN (select consent from UserConsent consent where consent.clientStorageProvider = :clientStorageProvider)"),
})
@Entity
@Table(name = "USER_CONSENT_CLIENT_SCOPE")
@IdClass(UserConsentClientScope.Key.class)
public class UserConsentClientScope {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_CONSENT_ID")
    protected UserConsent userConsent;

    @Id
    @Column(name = "SCOPE_ID")
    protected String scopeId;

    public UserConsent getUserConsent() {
        return userConsent;
    }

    public void setUserConsent(UserConsent userConsent) {
        this.userConsent = userConsent;
    }

    public String getScopeId() {
        return scopeId;
    }

    public void setScopeId(String scopeId) {
        this.scopeId = scopeId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserConsentClientScope)) return false;

        UserConsentClientScope that = (UserConsentClientScope) o;
        UserConsentClientScope.Key myKey = new UserConsentClientScope.Key(this.userConsent, this.scopeId);
        UserConsentClientScope.Key hisKey = new UserConsentClientScope.Key(that.userConsent, that.scopeId);
        return myKey.equals(hisKey);
    }

    @Override
    public int hashCode() {
        UserConsentClientScope.Key myKey = new UserConsentClientScope.Key(this.userConsent, this.scopeId);
        return myKey.hashCode();
    }

    public static class Key implements Serializable {

        protected UserConsent userConsent;

        protected String scopeId;

        public Key() {
        }

        public Key(UserConsent userConsent, String scopeId) {
            this.userConsent = userConsent;
            this.scopeId = scopeId;
        }

        public UserConsent getUserConsent() {
            return userConsent;
        }

        public String getScopeId() {
            return scopeId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            UserConsentClientScope.Key key = (UserConsentClientScope.Key) o;

            if (userConsent != null ? !userConsent.getId().equals(key.userConsent != null ? key.userConsent.getId() : null) : key.userConsent != null)
                return false;
            if (scopeId != null ? !scopeId.equals(key.scopeId) : key.scopeId != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = userConsent != null ? userConsent.getId().hashCode() : 0;
            result = 31 * result + (scopeId != null ? scopeId.hashCode() : 0);
            return result;
        }
    }
}
