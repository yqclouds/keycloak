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
@NamedQueries({
        @NamedQuery(name = "userMemberOf", query = "select m from UserGroupMembership m where m.user = :user and m.groupId = :groupId"),
        @NamedQuery(name = "userGroupMembership", query = "select m from UserGroupMembership m where m.user = :user"),
        @NamedQuery(name = "groupMembership", query = "select g.user from UserGroupMembership g where g.groupId = :groupId order by g.user.username"),
        @NamedQuery(name = "deleteUserGroupMembershipByRealm", query = "delete from  UserGroupMembership mapping where mapping.user IN (select u from User u where u.realmId=:realmId)"),
        @NamedQuery(name = "deleteUserGroupMembershipsByRealmAndLink", query = "delete from  UserGroupMembership mapping where mapping.user IN (select u from User u where u.realmId=:realmId and u.federationLink=:link)"),
        @NamedQuery(name = "deleteUserGroupMembershipsByGroup", query = "delete from UserGroupMembership m where m.groupId = :groupId"),
        @NamedQuery(name = "deleteUserGroupMembershipsByUser", query = "delete from UserGroupMembership m where m.user = :user"),
        @NamedQuery(name = "searchForUserCountInGroups", query = "select count(m.user) from UserGroupMembership m where m.user.realmId = :realmId and (m.user.serviceAccountClientLink is null) and " +
                "( lower(m.user.username) like :search or lower(concat(m.user.firstName, ' ', m.user.lastName)) like :search or m.user.email like :search ) and m.group.id in :groupIds"),
        @NamedQuery(name = "userCountInGroups", query = "select count(m.user) from UserGroupMembership m where m.user.realmId = :realmId and m.group.id in :groupIds")
})
@Table(name = "USER_GROUP_MEMBERSHIP")
@Entity
@IdClass(UserGroupMembership.Key.class)
public class UserGroupMembership {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    protected User user;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "GROUP_ID", insertable = false, updatable = false)
    protected Group group;

    @Id
    @Column(name = "GROUP_ID")
    protected String groupId;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserGroupMembership)) return false;

        UserGroupMembership key = (UserGroupMembership) o;

        if (!groupId.equals(key.groupId)) return false;
        if (!user.equals(key.user)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + groupId.hashCode();
        return result;
    }

    public static class Key implements Serializable {

        protected User user;

        protected String groupId;

        public Key() {
        }

        public Key(User user, String groupId) {
            this.user = user;
            this.groupId = groupId;
        }

        public User getUser() {
            return user;
        }

        public String getGroupId() {
            return groupId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (!groupId.equals(key.groupId)) return false;
            if (!user.equals(key.user)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = user.hashCode();
            result = 31 * result + groupId.hashCode();
            return result;
        }
    }

}
