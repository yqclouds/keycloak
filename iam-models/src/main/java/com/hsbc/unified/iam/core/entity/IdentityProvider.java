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
import java.util.Map;

/**
 * @author Pedro Igor
 */
@Entity
@Table(name = "IDENTITY_PROVIDER")
@NamedQueries({
        @NamedQuery(name = "findIdentityProviderByAlias", query = "select identityProvider from IdentityProvider identityProvider where identityProvider.alias = :alias")
})
public class IdentityProvider {

    @Id
    @Column(name = "INTERNAL_ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String internalId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;
    @Column(name = "ADD_TOKEN_ROLE")
    protected boolean addReadTokenRoleOnCreate;
    @Column(name = "PROVIDER_ID")
    private String providerId;
    @Column(name = "PROVIDER_ALIAS")
    private String alias;
    @Column(name = "PROVIDER_DISPLAY_NAME")
    private String displayName;
    @Column(name = "ENABLED")
    private boolean enabled;
    @Column(name = "TRUST_EMAIL")
    private boolean trustEmail;
    @Column(name = "STORE_TOKEN")
    private boolean storeToken;
    @Column(name = "LINK_ONLY")
    private boolean linkOnly;
    @Column(name = "AUTHENTICATE_BY_DEFAULT")
    private boolean authenticateByDefault;

    @Column(name = "FIRST_BROKER_LOGIN_FLOW_ID")
    private String firstBrokerLoginFlowId;

    @Column(name = "POST_BROKER_LOGIN_FLOW_ID")
    private String postBrokerLoginFlowId;

    @ElementCollection
    @MapKeyColumn(name = "NAME")
    @Column(name = "VALUE", columnDefinition = "TEXT")
    @CollectionTable(name = "IDENTITY_PROVIDER_CONFIG", joinColumns = {@JoinColumn(name = "IDENTITY_PROVIDER_ID")})
    private Map<String, String> config;

    public String getInternalId() {
        return this.internalId;
    }

    public void setInternalId(String internalId) {
        this.internalId = internalId;
    }

    public String getProviderId() {
        return this.providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    public Realm getRealm() {
        return this.realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getAlias() {
        return this.alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isStoreToken() {
        return this.storeToken;
    }

    public void setStoreToken(boolean storeToken) {
        this.storeToken = storeToken;
    }

    public boolean isAuthenticateByDefault() {
        return authenticateByDefault;
    }

    public void setAuthenticateByDefault(boolean authenticateByDefault) {
        this.authenticateByDefault = authenticateByDefault;
    }

    public boolean isLinkOnly() {
        return linkOnly;
    }

    public void setLinkOnly(boolean linkOnly) {
        this.linkOnly = linkOnly;
    }

    public String getFirstBrokerLoginFlowId() {
        return firstBrokerLoginFlowId;
    }

    public void setFirstBrokerLoginFlowId(String firstBrokerLoginFlowId) {
        this.firstBrokerLoginFlowId = firstBrokerLoginFlowId;
    }

    public String getPostBrokerLoginFlowId() {
        return postBrokerLoginFlowId;
    }

    public void setPostBrokerLoginFlowId(String postBrokerLoginFlowId) {
        this.postBrokerLoginFlowId = postBrokerLoginFlowId;
    }

    public Map<String, String> getConfig() {
        return this.config;
    }

    public void setConfig(Map<String, String> config) {
        this.config = config;
    }

    public boolean isAddReadTokenRoleOnCreate() {
        return addReadTokenRoleOnCreate;
    }

    public void setAddReadTokenRoleOnCreate(boolean addReadTokenRoleOnCreate) {
        this.addReadTokenRoleOnCreate = addReadTokenRoleOnCreate;
    }

    public boolean isTrustEmail() {
        return trustEmail;
    }

    public void setTrustEmail(boolean trustEmail) {
        this.trustEmail = trustEmail;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof IdentityProvider)) return false;

        IdentityProvider that = (IdentityProvider) o;

        if (!internalId.equals(that.internalId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return internalId.hashCode();
    }

}