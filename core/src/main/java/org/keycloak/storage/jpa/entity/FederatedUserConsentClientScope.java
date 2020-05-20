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

package org.keycloak.storage.jpa.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Entity
@Table(name = "FED_USER_CONSENT_CL_SCOPE")
@IdClass(FederatedUserConsentClientScope.Key.class)
public class FederatedUserConsentClientScope {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_CONSENT_ID")
    protected FederatedUserConsent userConsent;

    @Id
    @Column(name = "SCOPE_ID")
    protected String scopeId;

    public FederatedUserConsent getUserConsent() {
        return userConsent;
    }

    public void setUserConsent(FederatedUserConsent userConsent) {
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
        if (!(o instanceof FederatedUserConsentClientScope)) return false;

        FederatedUserConsentClientScope that = (FederatedUserConsentClientScope) o;
        FederatedUserConsentClientScope.Key myKey = new FederatedUserConsentClientScope.Key(this.userConsent, this.scopeId);
        FederatedUserConsentClientScope.Key hisKey = new FederatedUserConsentClientScope.Key(that.userConsent, that.scopeId);
        return myKey.equals(hisKey);
    }

    @Override
    public int hashCode() {
        FederatedUserConsentClientScope.Key myKey = new FederatedUserConsentClientScope.Key(this.userConsent, this.scopeId);
        return myKey.hashCode();
    }

    public static class Key implements Serializable {

        protected FederatedUserConsent userConsent;

        protected String scopeId;

        public Key() {
        }

        public Key(FederatedUserConsent userConsent, String scopeId) {
            this.userConsent = userConsent;
            this.scopeId = scopeId;
        }

        public FederatedUserConsent getUserConsent() {
            return userConsent;
        }

        public String getScopeId() {
            return scopeId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            FederatedUserConsentClientScope.Key key = (FederatedUserConsentClientScope.Key) o;

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
