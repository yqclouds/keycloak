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

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Table(name = "AUTHENTICATION_EXECUTION")
@Entity
public class AuthenticationExecution {
    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "FLOW_ID")
    protected AuthenticationFlow parentFlow;

    @Column(name = "AUTHENTICATOR")
    protected String authenticator;

    @Column(name = "AUTH_CONFIG")
    protected String authenticatorConfig;

    @Column(name = "AUTH_FLOW_ID")
    protected String flowId;

    @Column(name = "REQUIREMENT")
    protected AuthenticationExecutionRequirement requirement;

    @Column(name = "PRIORITY")
    protected int priority;

    @Column(name = "AUTHENTICATOR_FLOW")
    private boolean autheticatorFlow;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(String authenticator) {
        this.authenticator = authenticator;
    }

    public AuthenticationExecutionRequirement getRequirement() {
        return requirement;
    }

    public void setRequirement(AuthenticationExecutionRequirement requirement) {
        this.requirement = requirement;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public boolean isAutheticatorFlow() {
        return autheticatorFlow;
    }

    public void setAutheticatorFlow(boolean autheticatorFlow) {
        this.autheticatorFlow = autheticatorFlow;
    }

    public AuthenticationFlow getParentFlow() {
        return parentFlow;
    }

    public void setParentFlow(AuthenticationFlow flow) {
        this.parentFlow = flow;
    }

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public String getAuthenticatorConfig() {
        return authenticatorConfig;
    }

    public void setAuthenticatorConfig(String authenticatorConfig) {
        this.authenticatorConfig = authenticatorConfig;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof AuthenticationExecution)) return false;

        AuthenticationExecution that = (AuthenticationExecution) o;

        if (!id.equals(that.getId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
