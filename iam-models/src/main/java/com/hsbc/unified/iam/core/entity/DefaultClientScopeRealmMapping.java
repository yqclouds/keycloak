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

package com.hsbc.unified.iam.core.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Binding between realm and default clientScope
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@NamedQueries({
        @NamedQuery(name = "defaultClientScopeRealmMappingIdsByRealm", query = "select m.clientScope.id from DefaultClientScopeRealmMapping m where m.realm = :realm and m.defaultScope = :defaultScope"),
        @NamedQuery(name = "deleteDefaultClientScopeRealmMapping", query = "delete from DefaultClientScopeRealmMapping where realm = :realm and clientScope = :clientScope"),
        @NamedQuery(name = "deleteDefaultClientScopeRealmMappingByRealm", query = "delete from DefaultClientScopeRealmMapping where realm = :realm")
})
@Entity
@Table(name = "DEFAULT_CLIENT_SCOPE")
@IdClass(DefaultClientScopeRealmMapping.Key.class)
public class DefaultClientScopeRealmMapping {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "SCOPE_ID")
    protected ClientScope clientScope;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;

    @Column(name = "DEFAULT_SCOPE")
    protected boolean defaultScope;

    public ClientScope getClientScope() {
        return clientScope;
    }

    public void setClientScope(ClientScope clientScope) {
        this.clientScope = clientScope;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public boolean isDefaultScope() {
        return defaultScope;
    }

    public void setDefaultScope(boolean defaultScope) {
        this.defaultScope = defaultScope;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!(o instanceof DefaultClientScopeRealmMapping)) return false;

        DefaultClientScopeRealmMapping key = (DefaultClientScopeRealmMapping) o;

        if (clientScope != null ? !clientScope.getId().equals(key.clientScope != null ? key.clientScope.getId() : null) : key.clientScope != null)
            return false;
        if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientScope != null ? clientScope.getId().hashCode() : 0;
        result = 31 * result + (realm != null ? realm.getId().hashCode() : 0);
        return result;
    }

    public static class Key implements Serializable {

        protected ClientScope clientScope;

        protected Realm realm;

        public Key() {
        }

        public Key(ClientScope clientScope, Realm realm) {
            this.clientScope = clientScope;
            this.realm = realm;
        }

        public ClientScope getClientScope() {
            return clientScope;
        }

        public Realm getRealm() {
            return realm;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            DefaultClientScopeRealmMapping.Key key = (DefaultClientScopeRealmMapping.Key) o;

            if (clientScope != null ? !clientScope.getId().equals(key.clientScope != null ? key.clientScope.getId() : null) : key.clientScope != null)
                return false;
            if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = clientScope != null ? clientScope.getId().hashCode() : 0;
            result = 31 * result + (realm != null ? realm.getId().hashCode() : 0);
            return result;
        }
    }
}
