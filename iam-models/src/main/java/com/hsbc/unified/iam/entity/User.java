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

import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;
import org.hibernate.annotations.Nationalized;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@NamedQueries({
        @NamedQuery(name = "getAllUsersByRealm", query = "select u from User u where u.realmId = :realmId order by u.username"),
        @NamedQuery(name = "getAllUsersByRealmExcludeServiceAccount", query = "select u from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) order by u.username"),
        @NamedQuery(name = "searchForUser", query = "select u from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) and " +
                "( lower(u.username) like :search or lower(concat(coalesce(u.firstName, ''), ' ', coalesce(u.lastName, ''))) like :search or u.email like :search ) order by u.username"),
        @NamedQuery(name = "searchForUserCount", query = "select count(u) from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null) and " +
                "( lower(u.username) like :search or lower(concat(coalesce(u.firstName, ''), ' ', coalesce(u.lastName, ''))) like :search or u.email like :search )"),
        @NamedQuery(name = "getRealmUserByUsername", query = "select u from User u where u.username = :username and u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserByEmail", query = "select u from User u where u.email = :email and u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserByLastName", query = "select u from User u where u.lastName = :lastName and u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserByFirstLastName", query = "select u from User u where u.firstName = :first and u.lastName = :last and u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserByServiceAccount", query = "select u from User u where u.serviceAccountClientLink = :clientInternalId and u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserCount", query = "select count(u) from User u where u.realmId = :realmId"),
        @NamedQuery(name = "getRealmUserCountExcludeServiceAccount", query = "select count(u) from User u where u.realmId = :realmId and (u.serviceAccountClientLink is null)"),
        @NamedQuery(name = "getRealmUsersByAttributeNameAndValue", query = "select u from User u join u.attributes attr " +
                "where u.realmId = :realmId and attr.name = :name and attr.value = :value"),
        @NamedQuery(name = "deleteUsersByRealm", query = "delete from User u where u.realmId = :realmId"),
        @NamedQuery(name = "deleteUsersByRealmAndLink", query = "delete from User u where u.realmId = :realmId and u.federationLink=:link"),
        @NamedQuery(name = "unlinkUsers", query = "update User u set u.federationLink = null where u.realmId = :realmId and u.federationLink=:link")
})
@Entity
@Table(name = "USER_ENTITY", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"REALM_ID", "USERNAME"}),
        @UniqueConstraint(columnNames = {"REALM_ID", "EMAIL_CONSTRAINT"})
})
public class User {
    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Nationalized
    @Column(name = "USERNAME")
    protected String username;
    @Nationalized
    @Column(name = "FIRST_NAME")
    protected String firstName;
    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp;
    @Nationalized
    @Column(name = "LAST_NAME")
    protected String lastName;
    @Column(name = "EMAIL")
    protected String email;
    @Column(name = "ENABLED")
    protected boolean enabled;
    @Column(name = "EMAIL_VERIFIED")
    protected boolean emailVerified;

    // This is necessary to be able to dynamically switch unique email constraints on and off in the realm settings
    @Column(name = "EMAIL_CONSTRAINT")
    protected String emailConstraint = UUID.randomUUID().toString();

    @Column(name = "REALM_ID")
    protected String realmId;

    @OneToMany(cascade = CascadeType.REMOVE, orphanRemoval = true, mappedBy = "user")
    @Fetch(FetchMode.SELECT)
    @BatchSize(size = 20)
    protected Collection<UserAttribute> attributes = new ArrayList<UserAttribute>();

    @OneToMany(cascade = CascadeType.REMOVE, orphanRemoval = true, mappedBy = "user")
    @Fetch(FetchMode.SELECT)
    @BatchSize(size = 20)
    protected Collection<UserRequiredAction> requiredActions = new ArrayList<UserRequiredAction>();

    @OneToMany(cascade = CascadeType.REMOVE, orphanRemoval = true, mappedBy = "user")
    @Fetch(FetchMode.SELECT)
    @BatchSize(size = 20)
    protected Collection<Credential> credentials = new ArrayList<Credential>();

    @Column(name = "FEDERATION_LINK")
    protected String federationLink;

    @Column(name = "SERVICE_ACCOUNT_CLIENT_LINK")
    protected String serviceAccountClientLink;

    @Column(name = "NOT_BEFORE")
    protected int notBefore;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(Long timestamp) {
        createdTimestamp = timestamp;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email, boolean allowDuplicate) {
        this.email = email;
        this.emailConstraint = email == null || allowDuplicate ? UUID.randomUUID().toString() : email;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getEmailConstraint() {
        return emailConstraint;
    }

    public void setEmailConstraint(String emailConstraint) {
        this.emailConstraint = emailConstraint;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Collection<UserAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(Collection<UserAttribute> attributes) {
        this.attributes = attributes;
    }

    public Collection<UserRequiredAction> getRequiredActions() {
        return requiredActions;
    }

    public void setRequiredActions(Collection<UserRequiredAction> requiredActions) {
        this.requiredActions = requiredActions;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public Collection<Credential> getCredentials() {
        return credentials;
    }

    public void setCredentials(Collection<Credential> credentials) {
        this.credentials = credentials;
    }

    public String getFederationLink() {
        return federationLink;
    }

    public void setFederationLink(String federationLink) {
        this.federationLink = federationLink;
    }

    public String getServiceAccountClientLink() {
        return serviceAccountClientLink;
    }

    public void setServiceAccountClientLink(String serviceAccountClientLink) {
        this.serviceAccountClientLink = serviceAccountClientLink;
    }

    public int getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(int notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof User)) return false;

        User that = (User) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
