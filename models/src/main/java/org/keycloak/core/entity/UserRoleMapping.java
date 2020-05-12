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

package org.keycloak.core.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@NamedQueries({
        @NamedQuery(name = "usersInRole", query = "select u from UserRoleMapping m, User u where m.roleId=:roleId and u.id=m.user"),
        @NamedQuery(name = "userHasRole", query = "select m from UserRoleMapping m where m.user = :user and m.roleId = :roleId"),
        @NamedQuery(name = "userRoleMappings", query = "select m from UserRoleMapping m where m.user = :user"),
        @NamedQuery(name = "userRoleMappingIds", query = "select m.roleId from UserRoleMapping m where m.user = :user"),
        @NamedQuery(name = "deleteUserRoleMappingsByRealm", query = "delete from  UserRoleMapping mapping where mapping.user IN (select u from User u where u.realmId=:realmId)"),
        @NamedQuery(name = "deleteUserRoleMappingsByRealmAndLink", query = "delete from  UserRoleMapping mapping where mapping.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name = "deleteUserRoleMappingsByRole", query = "delete from UserRoleMapping m where m.roleId = :roleId"),
        @NamedQuery(name = "deleteUserRoleMappingsByUser", query = "delete from UserRoleMapping m where m.user = :user"),
        @NamedQuery(name = "grantRoleToAllUsers", query = "insert into UserRoleMapping (roleId, user) select role.id, user from Role role, User user where role.id = :roleId AND role.realm.id = :realmId AND user.realmId = :realmId")

})
@Table(name = "USER_ROLE_MAPPING")
@Entity
@IdClass(UserRoleMapping.Key.class)
public class UserRoleMapping {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    protected User user;

    @Id
    @Column(name = "ROLE_ID")
    protected String roleId;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserRoleMapping)) return false;

        UserRoleMapping key = (UserRoleMapping) o;

        if (!roleId.equals(key.roleId)) return false;
        if (!user.equals(key.user)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + roleId.hashCode();
        return result;
    }

    public static class Key implements Serializable {

        protected User user;

        protected String roleId;

        public Key() {
        }

        public Key(User user, String roleId) {
            this.user = user;
            this.roleId = roleId;
        }

        public User getUser() {
            return user;
        }

        public String getRoleId() {
            return roleId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (!roleId.equals(key.roleId)) return false;
            if (!user.equals(key.user)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = user.hashCode();
            result = 31 * result + roleId.hashCode();
            return result;
        }
    }

}
