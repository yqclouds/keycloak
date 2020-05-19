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
import java.io.Serializable;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Table(name = "FEDERATED_IDENTITY")
@Entity
@IdClass(FederatedIdentity.Key.class)
public class FederatedIdentity {

    @Column(name = "REALM_ID")
    protected String realmId;
    @Id
    @Column(name = "IDENTITY_PROVIDER")
    protected String identityProvider;
    @Column(name = "FEDERATED_USER_ID")
    protected String userId;
    @Column(name = "FEDERATED_USERNAME")
    protected String userName;
    @Column(name = "TOKEN")
    protected String token;
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    private User user;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(String identityProvider) {
        this.identityProvider = identityProvider;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof FederatedIdentity)) return false;

        FederatedIdentity key = (FederatedIdentity) o;

        if (identityProvider != null ? !identityProvider.equals(key.identityProvider) : key.identityProvider != null)
            return false;
        if (user != null ? !user.getId().equals(key.user != null ? key.user.getId() : null) : key.user != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user != null ? user.getId().hashCode() : 0;
        result = 31 * result + (identityProvider != null ? identityProvider.hashCode() : 0);
        return result;
    }

    public static class Key implements Serializable {

        protected User user;

        protected String identityProvider;

        public Key() {
        }

        public Key(User user, String identityProvider) {
            this.user = user;
            this.identityProvider = identityProvider;
        }

        public User getUser() {
            return user;
        }

        public String getIdentityProvider() {
            return identityProvider;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (identityProvider != null ? !identityProvider.equals(key.identityProvider) : key.identityProvider != null)
                return false;
            if (user != null ? !user.getId().equals(key.user != null ? key.user.getId() : null) : key.user != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = user != null ? user.getId().hashCode() : 0;
            result = 31 * result + (identityProvider != null ? identityProvider.hashCode() : 0);
            return result;
        }
    }


}
