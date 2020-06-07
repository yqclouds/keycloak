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

package org.keycloak.authentication;

import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

import java.util.Collections;
import java.util.List;

/**
 * This interface is for users that want to add custom authenticators to an authentication flow.
 * You must implement this interface as well as an AuthenticatorFactory.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface Authenticator extends Provider {

    /**
     * Initial call for the authenticator.  This method should check the current HTTP request to determine if the request
     * satifies the Authenticator's requirements.  If it doesn't, it should send back a challenge response by calling
     * the AuthenticationFlowContext.challenge(Response).  If this challenge is a authentication, the action URL
     * of the form must point to
     * <p>
     * /realms/{realm}/login-actions/authenticate?code={session-code}&execution={executionId}
     * <p>
     * or
     * <p>
     * /realms/{realm}/login-actions/registration?code={session-code}&execution={executionId}
     * <p>
     * {session-code} pertains to the code generated from AuthenticationFlowContext.generateAccessCode().  The {executionId}
     * pertains to the AuthenticationExecutionModel.getId() value obtained from AuthenticationFlowContext.getExecution().
     * <p>
     * The action URL will invoke the action() method described below.
     */
    void authenticate(AuthenticationFlowContext context);

    /**
     * Called from a form action invocation.
     */
    void action(AuthenticationFlowContext context);

    /**
     * Does this authenticator require that the user has already been identified?  That AuthenticatorContext.getUser() is not null?
     */
    boolean requiresUser();

    /**
     * Is this authenticator configured for this user.
     */
    boolean configuredFor(RealmModel realm, UserModel user);

    /**
     * Set actions to configure authenticator
     */
    void setRequiredActions(RealmModel realm, UserModel user);

    /**
     * Overwrite this if the authenticator is associated with
     */
    default List<RequiredActionFactory> getRequiredActions() {
        return Collections.emptyList();
    }

    /**
     * Checks if all required actions are configured in the realm and are enabled
     */
    default boolean areRequiredActionsEnabled(RealmModel realm) {
        for (RequiredActionFactory raf : getRequiredActions()) {
            RequiredActionProviderModel rafpm = realm.getRequiredActionProviderByAlias(raf.getId());
            if (rafpm == null) {
                return false;
            }
            if (!rafpm.isEnabled()) {
                return false;
            }
        }
        return true;
    }
}
