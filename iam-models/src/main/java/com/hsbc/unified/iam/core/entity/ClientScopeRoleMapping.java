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

package com.hsbc.unified.iam.core.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Table(name = "CLIENT_SCOPE_ROLE_MAPPING")
@Entity
@IdClass(ClientScopeRoleMapping.Key.class)
public class ClientScopeRoleMapping {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "SCOPE_ID")
    protected ClientScope clientScope;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ROLE_ID")
    protected Role role;

    public ClientScope getClientScope() {
        return clientScope;
    }

    public void setClientScope(ClientScope clientScope) {
        this.clientScope = clientScope;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!(o instanceof ClientScopeRoleMapping)) return false;

        ClientScopeRoleMapping key = (ClientScopeRoleMapping) o;

        if (clientScope != null ? !clientScope.getId().equals(key.clientScope != null ? key.clientScope.getId() : null) : key.clientScope != null)
            return false;
        if (role != null ? !role.getId().equals(key.role != null ? key.role.getId() : null) : key.role != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientScope != null ? clientScope.getId().hashCode() : 0;
        result = 31 * result + (role != null ? role.getId().hashCode() : 0);
        return result;
    }

    public static class Key implements Serializable {

        protected ClientScope clientScope;

        protected Role role;

        public Key() {
        }

        public Key(ClientScope clientScope, Role role) {
            this.clientScope = clientScope;
            this.role = role;
        }

        public ClientScope getClientScope() {
            return clientScope;
        }

        public Role getRole() {
            return role;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (clientScope != null ? !clientScope.getId().equals(key.clientScope != null ? key.clientScope.getId() : null) : key.clientScope != null)
                return false;
            if (role != null ? !role.getId().equals(key.role != null ? key.role.getId() : null) : key.role != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = clientScope != null ? clientScope.getId().hashCode() : 0;
            result = 31 * result + (role != null ? role.getId().hashCode() : 0);
            return result;
        }
    }
}
