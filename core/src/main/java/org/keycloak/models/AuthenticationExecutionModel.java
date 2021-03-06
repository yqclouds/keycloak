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

package org.keycloak.models;

import com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement;

import java.io.Serializable;
import java.util.Comparator;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AuthenticationExecutionModel implements Serializable {

    private String id;
    private String authenticatorConfig;
    private String authenticator;
    private String flowId;
    private boolean authenticatorFlow;
    private AuthenticationExecutionRequirement requirement;
    private int priority;
    private String parentFlow;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAuthenticatorConfig() {
        return authenticatorConfig;
    }

    public void setAuthenticatorConfig(String authenticatorConfig) {
        this.authenticatorConfig = authenticatorConfig;
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

    public String getParentFlow() {
        return parentFlow;
    }

    public void setParentFlow(String parentFlow) {
        this.parentFlow = parentFlow;
    }

    /**
     * If this execution is a flow, this is the flowId pointing to an AuthenticationFlowModel
     *
     * @return
     */
    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    /**
     * Is the referenced authenticator a flow?
     *
     * @return
     */
    public boolean isAuthenticatorFlow() {
        return authenticatorFlow;
    }

    public void setAuthenticatorFlow(boolean authenticatorFlow) {
        this.authenticatorFlow = authenticatorFlow;
    }

    public boolean isRequired() {
        return requirement == AuthenticationExecutionRequirement.REQUIRED;
    }

    public boolean isConditional() {
        return requirement == AuthenticationExecutionRequirement.CONDITIONAL;
    }

    public boolean isAlternative() {
        return requirement == AuthenticationExecutionRequirement.ALTERNATIVE;
    }

    public boolean isDisabled() {
        return requirement == AuthenticationExecutionRequirement.DISABLED;
    }

    public boolean isEnabled() {
        return requirement != AuthenticationExecutionRequirement.DISABLED;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AuthenticationExecutionModel that = (AuthenticationExecutionModel) o;

        if (id == null || that.id == null) return false;
        return id.equals(that.id);

    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    public static class ExecutionComparator implements Comparator<AuthenticationExecutionModel> {
        public static final ExecutionComparator SINGLETON = new ExecutionComparator();

        @Override
        public int compare(AuthenticationExecutionModel o1, AuthenticationExecutionModel o2) {
            return o1.priority - o2.priority;
        }
    }
}
