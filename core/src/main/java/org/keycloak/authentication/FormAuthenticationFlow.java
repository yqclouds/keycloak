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

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.Constants;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class FormAuthenticationFlow implements AuthenticationFlow {
    private final List<AuthenticationExecutionModel> formActionExecutions;
    private final FormAuthenticator formAuthenticator;
    AuthenticationProcessor processor;
    AuthenticationExecutionModel formExecution;

    public FormAuthenticationFlow(AuthenticationProcessor processor, AuthenticationExecutionModel execution) {
        this.processor = processor;
        this.formExecution = execution;
        formActionExecutions = processor.getRealm().getAuthenticationExecutions(execution.getFlowId());
        formAuthenticator = processor.getSession().getProvider(FormAuthenticator.class, execution.getAuthenticator());
    }

    @Override
    public Response processAction(String actionExecution) {
        if (!actionExecution.equals(formExecution.getId())) {
            throw new AuthenticationFlowException("action is not current execution", AuthenticationFlowError.INTERNAL_ERROR);
        }
        Map<String, AuthenticationSessionModel.ExecutionStatus> executionStatus = new HashMap<>();
        List<FormAction> requiredActions = new LinkedList<>();
        List<ValidationContextImpl> successes = new LinkedList<>();
        List<ValidationContextImpl> errors = new LinkedList<>();
        for (AuthenticationExecutionModel formActionExecution : formActionExecutions) {
            if (!formActionExecution.isEnabled()) {
                executionStatus.put(formActionExecution.getId(), AuthenticationSessionModel.ExecutionStatus.SKIPPED);
                continue;
            }
            FormActionFactory factory = (FormActionFactory) processor.getSession().getSessionFactory().getProviderFactory(FormAction.class, formActionExecution.getAuthenticator());
            FormAction action = factory.create();

            UserModel authUser = processor.getAuthenticationSession().getAuthenticatedUser();
            if (action.requiresUser() && authUser == null) {
                throw new AuthenticationFlowException("form action: " + formExecution.getAuthenticator() + " requires user", AuthenticationFlowError.UNKNOWN_USER);
            }
            boolean configuredFor = false;
            if (action.requiresUser() && authUser != null) {
                configuredFor = action.configuredFor(processor.getRealm(), authUser);
                if (!configuredFor) {
                    if (formActionExecution.isRequired()) {
                        if (factory.isUserSetupAllowed()) {
                            AuthenticationProcessor.LOG.debug("authenticator SETUP_REQUIRED: {}", formExecution.getAuthenticator());
                            executionStatus.put(formActionExecution.getId(), AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED);
                            requiredActions.add(action);
                            continue;
                        } else {
                            throw new AuthenticationFlowException(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
                        }
                    } else if (formActionExecution.isConditional()) {
                        executionStatus.put(formActionExecution.getId(), AuthenticationSessionModel.ExecutionStatus.SKIPPED);
                        continue;
                    }
                }
            }

            ValidationContextImpl result = new ValidationContextImpl(formActionExecution, action);
            action.validate(result);
            if (result.success) {
                executionStatus.put(formActionExecution.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);
                successes.add(result);
            } else {
                executionStatus.put(formActionExecution.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                errors.add(result);
            }
        }

        if (!errors.isEmpty()) {
            processor.logFailure();
            List<FormMessage> messages = new LinkedList<>();
            Set<String> fields = new HashSet<>();
            for (ValidationContextImpl v : errors) {
                for (FormMessage m : v.errors) {
                    if (!fields.contains(m.getField())) {
                        if (v.excludeOthers) {
                            fields.clear();
                            messages.clear();
                        }

                        fields.add(m.getField());
                        messages.add(m);

                        if (v.excludeOthers) {
                            break;
                        }
                    }
                }
            }
            ValidationContextImpl first = errors.get(0);
            first.getEvent().error(first.error);
            return renderForm(first.formData, messages);
        }

        for (ValidationContextImpl context : successes) {
            context.action.success(context);
        }
        // set status and required actions only if form is fully successful
        for (Map.Entry<String, AuthenticationSessionModel.ExecutionStatus> entry : executionStatus.entrySet()) {
            processor.getAuthenticationSession().setExecutionStatus(entry.getKey(), entry.getValue());
        }
        for (FormAction action : requiredActions) {
            action.setRequiredActions(processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser());

        }
        processor.getAuthenticationSession().setExecutionStatus(actionExecution, AuthenticationSessionModel.ExecutionStatus.SUCCESS);
        processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
        return null;
    }

    public URI getActionUrl(String executionId, String code) {
        ClientModel client = processor.getAuthenticationSession().getClient();
        return LoginActionsService.registrationFormProcessor(processor.getUriInfo())
                .queryParam(LoginActionsService.SESSION_CODE, code)
                .queryParam(Constants.EXECUTION, executionId)
                .queryParam(Constants.CLIENT_ID, client.getClientId())
                .queryParam(Constants.TAB_ID, processor.getAuthenticationSession().getTabId())
                .build(processor.getRealm().getName());
    }

    @Override
    public Response processFlow() {
        return renderForm(null, null);
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;

    public Response renderForm(MultivaluedMap<String, String> formData, List<FormMessage> errors) {
        String executionId = formExecution.getId();
        processor.getAuthenticationSession().setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, executionId);
        String code = processor.generateCode();
        URI actionUrl = getActionUrl(executionId, code);
        LoginFormsProvider form = this.loginFormsProvider
                .setAuthenticationSession(processor.getAuthenticationSession())
                .setActionUri(actionUrl)
                .setExecution(executionId)
                .setClientSessionCode(code)
                .setFormData(formData)
                .setErrors(errors);
        for (AuthenticationExecutionModel formActionExecution : formActionExecutions) {
            if (!formActionExecution.isEnabled()) continue;
            FormAction action = processor.getSession().getProvider(FormAction.class, formActionExecution.getAuthenticator());
            FormContext result = new FormContextImpl(formActionExecution);
            action.buildPage(result, form);
        }
        FormContext context = new FormContextImpl(formExecution);
        return formAuthenticator.render(context, form);
    }

    @Override
    public boolean isSuccessful() {
        return false;
    }

    private class FormContextImpl implements FormContext {
        AuthenticationExecutionModel executionModel;
        AuthenticatorConfigModel authenticatorConfig;

        private FormContextImpl(AuthenticationExecutionModel executionModel) {
            this.executionModel = executionModel;
        }

        @Override
        public EventBuilder newEvent() {
            return processor.newEvent();
        }

        @Override
        public EventBuilder getEvent() {
            return processor.getEvent();
        }

        @Override
        public AuthenticationExecutionModel getExecution() {
            return executionModel;
        }

        @Override
        public AuthenticatorConfigModel getAuthenticatorConfig() {
            if (executionModel.getAuthenticatorConfig() == null) return null;
            if (authenticatorConfig != null) return authenticatorConfig;
            authenticatorConfig = getRealm().getAuthenticatorConfigById(executionModel.getAuthenticatorConfig());
            return authenticatorConfig;
        }

        @Override
        public UserModel getUser() {
            return getAuthenticationSession().getAuthenticatedUser();
        }

        @Override
        public void setUser(UserModel user) {
            processor.setAutheticatedUser(user);
        }

        @Override
        public RealmModel getRealm() {
            return processor.getRealm();
        }

        @Override
        public AuthenticationSessionModel getAuthenticationSession() {
            return processor.getAuthenticationSession();
        }

        @Override
        public ClientConnection getConnection() {
            return processor.getConnection();
        }

        @Override
        public UriInfo getUriInfo() {
            return processor.getUriInfo();
        }

        @Override
        public KeycloakSession getSession() {
            return processor.getSession();
        }

        @Override
        public HttpRequest getHttpRequest() {
            return processor.getRequest();
        }

    }

    private class ValidationContextImpl extends FormContextImpl implements ValidationContext {
        FormAction action;
        String error;
        boolean excludeOthers;
        boolean success;
        List<FormMessage> errors = null;
        MultivaluedMap<String, String> formData = null;

        private ValidationContextImpl(AuthenticationExecutionModel executionModel, FormAction action) {
            super(executionModel);
            this.action = action;
        }

        @Override
        public void validationError(MultivaluedMap<String, String> formData, List<FormMessage> errors) {
            this.errors = errors;
            this.formData = formData;
        }

        public void error(String error) {
            this.error = error;
        }

        @Override
        public void success() {
            success = true;
        }

        @Override
        public void excludeOtherErrors() {
            excludeOthers = true;
        }
    }
}
