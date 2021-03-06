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

package org.keycloak.services.resources;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.Constants;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.RestartLoginCookie;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.AuthenticationFlowURLHelper;
import org.keycloak.services.util.BrowserHistoryHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;


public class SessionCodeChecks {

    private static final Logger LOG = LoggerFactory.getLogger(SessionCodeChecks.class);
    private final RealmModel realm;
    private final UriInfo uriInfo;
    private final HttpRequest request;
    private final ClientConnection clientConnection;
    private final EventBuilder event;
    private final String code;
    private final String execution;
    private final String clientId;
    private final String tabId;
    private final String flowPath;
    private final String authSessionId;
    private AuthenticationSessionModel authSession;
    private ClientSessionCode<AuthenticationSessionModel> clientCode;
    private Response response;
    private boolean actionRequest;

    @Autowired
    private KeycloakContext keycloakContext;

    public SessionCodeChecks(RealmModel realm, UriInfo uriInfo, HttpRequest request, ClientConnection clientConnection, EventBuilder event,
                             String authSessionId, String code, String execution, String clientId, String tabId, String flowPath) {
        this.realm = realm;
        this.uriInfo = uriInfo;
        this.request = request;
        this.clientConnection = clientConnection;
        this.event = event;

        this.code = code;
        this.execution = execution;
        this.clientId = clientId;
        this.tabId = tabId;
        this.flowPath = flowPath;
        this.authSessionId = authSessionId;
    }


    public AuthenticationSessionModel getAuthenticationSession() {
        return authSession;
    }


    private boolean failed() {
        return response != null;
    }


    public Response getResponse() {
        return response;
    }


    public ClientSessionCode<AuthenticationSessionModel> getClientCode() {
        return clientCode;
    }

    public boolean isActionRequest() {
        return actionRequest;
    }


    private boolean checkSsl() {
        if (uriInfo.getBaseUri().getScheme().equals("https")) {
            return true;
        } else {
            return !realm.getSslRequired().isRequired(clientConnection);
        }
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;
    @Autowired
    private ErrorPage errorPage;

    public AuthenticationSessionModel initialVerifyAuthSession() {
        // Basic realm checks
        if (!checkSsl()) {
            event.error(Errors.SSL_REQUIRED);
            response = errorPage.error(null, Response.Status.BAD_REQUEST, Messages.HTTPS_REQUIRED);
            return null;
        }
        if (!realm.isEnabled()) {
            event.error(Errors.REALM_DISABLED);
            response = errorPage.error(null, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
            return null;
        }

        // Setup client to be shown on error/info page based on "client_id" parameter
        LOG.debug("Will use client '{}' in back-to-application link", clientId);
        ClientModel client = null;
        if (clientId != null) {
            client = realm.getClientByClientId(clientId);
        }
        if (client != null) {
            keycloakContext.setClient(client);
        }


        // object retrieve
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager();
        AuthenticationSessionModel authSession = null;
        if (authSessionId != null)
            authSession = authSessionManager.getAuthenticationSessionByIdAndClient(realm, authSessionId, client, tabId);
        AuthenticationSessionModel authSessionCookie = authSessionManager.getCurrentAuthenticationSession(realm, client, tabId);

        if (authSession != null && authSessionCookie != null && !authSession.getParentSession().getId().equals(authSessionCookie.getParentSession().getId())) {
            event.detail(Details.REASON, "cookie does not match auth_session query parameter");
            event.error(Errors.INVALID_CODE);
            response = errorPage.error(null, Response.Status.BAD_REQUEST, Messages.INVALID_CODE);
            return null;

        }

        if (authSession != null) {
            loginFormsProvider.setAuthenticationSession(authSession);
            return authSession;
        }

        if (authSessionCookie != null) {
            loginFormsProvider.setAuthenticationSession(authSessionCookie);
            return authSessionCookie;
        }

        // See if we are already authenticated and userSession with same ID exists.
        UserSessionModel userSession = authSessionManager.getUserSessionFromAuthCookie(realm);

        if (userSession != null) {
            LoginFormsProvider loginForm = this.loginFormsProvider.setAuthenticationSession(authSession)
                    .setSuccess(Messages.ALREADY_LOGGED_IN);

            if (client == null) {
                loginForm.setAttribute(Constants.SKIP_LINK, true);
            }

            response = loginForm.createInfoPage();
            return null;
        }

        // Otherwise just try to restart from the cookie
        RootAuthenticationSessionModel existingRootAuthSession = authSessionManager.getCurrentRootAuthenticationSession(realm);
        response = restartAuthenticationSessionFromCookie(existingRootAuthSession);
        return null;
    }


    public boolean initialVerify() {
        // Basic realm checks and authenticationSession retrieve
        authSession = initialVerifyAuthSession();
        if (authSession == null) {
            return false;
        }

        // Check cached response from previous action request
        response = BrowserHistoryHelper.getInstance().loadSavedResponse(authSession);
        if (response != null) {
            return false;
        }

        // Client checks
        event.detail(Details.CODE_ID, authSession.getParentSession().getId());
        ClientModel client = authSession.getClient();
        if (client == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            response = errorPage.error(authSession, Response.Status.BAD_REQUEST, Messages.UNKNOWN_LOGIN_REQUESTER);
            clientCode.removeExpiredClientSession();
            return false;
        }

        event.client(client);
        keycloakContext.setClient(client);

        if (!client.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            response = errorPage.error(authSession, Response.Status.BAD_REQUEST, Messages.LOGIN_REQUESTER_NOT_ENABLED);
            clientCode.removeExpiredClientSession();
            return false;
        }


        // Check if it's action or not
        if (code == null) {
            String lastExecFromSession = authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
            String lastFlow = authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH);

            // Check if we transitted between flows (eg. clicking "register" on login screen)
            if (execution == null && !flowPath.equals(lastFlow)) {
                LOG.debug("Transition between flows! Current flow: {}, Previous flow: {}", flowPath, lastFlow);

                // Don't allow moving to different flow if I am on requiredActions already
                if (AuthenticationSessionModel.Action.AUTHENTICATE.name().equals(authSession.getAction())) {
                    authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, flowPath);
                    authSession.removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
                    lastExecFromSession = null;
                }
            }

            if (execution == null || execution.equals(lastExecFromSession)) {
                // Allow refresh of previous page
                clientCode = new ClientSessionCode<>(realm, authSession);
                actionRequest = false;

                // Allow refresh, but rewrite browser history
                if (execution == null && lastExecFromSession != null) {
                    LOG.debug("Parameter 'execution' is not in the request, but flow wasn't changed. Will update browser history");
                    request.setAttribute(BrowserHistoryHelper.SHOULD_UPDATE_BROWSER_HISTORY, true);
                }

                return true;
            } else {
                response = showPageExpired(authSession);
                return false;
            }
        } else {
            ClientSessionCode.ParseResult<AuthenticationSessionModel> result = ClientSessionCode.parseResult(code, tabId, realm, client, event, authSession);
            clientCode = result.getCode();
            if (clientCode == null) {

                // In case that is replayed action, but sent to the same FORM like actual FORM, we just re-render the page
                if (ObjectUtil.isEqualOrBothNull(execution, authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION))) {
                    String latestFlowPath = authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH);
                    URI redirectUri = getLastExecutionUrl(latestFlowPath, execution, tabId);

                    LOG.debug("Invalid action code, but execution matches. So just redirecting to {}", redirectUri);
                    authSession.setAuthNote(LoginActionsService.FORWARDED_ERROR_MESSAGE_NOTE, Messages.EXPIRED_ACTION);
                    response = Response.status(Response.Status.FOUND).location(redirectUri).build();
                } else {
                    response = showPageExpired(authSession);
                }
                return false;
            }


            actionRequest = true;
            if (execution != null) {
                authSession.setAuthNote(AuthenticationProcessor.LAST_PROCESSED_EXECUTION, execution);
            }
            return true;
        }
    }


    public boolean verifyActiveAndValidAction(String expectedAction, ClientSessionCode.ActionType actionType) {
        if (failed()) {
            return false;
        }

        if (!isActionActive(actionType)) {
            return false;
        }

        if (!clientCode.isValidAction(expectedAction)) {
            AuthenticationSessionModel authSession = getAuthenticationSession();
            if (AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name().equals(authSession.getAction())) {
                LOG.debug("Incorrect action '{}' . User authenticated already.", authSession.getAction());
                response = showPageExpired(authSession);
                return false;
            } else {
                LOG.error("Bad action. Expected action '{}', current action '{}'", expectedAction, authSession.getAction());
                response = errorPage.error(authSession, Response.Status.BAD_REQUEST, Messages.EXPIRED_CODE);
                return false;
            }
        }

        return true;
    }


    private boolean isActionActive(ClientSessionCode.ActionType actionType) {
        if (!clientCode.isActionActive(actionType)) {
            event.clone().error(Errors.EXPIRED_CODE);

            AuthenticationProcessor.resetFlow(authSession, LoginActionsService.AUTHENTICATE_PATH);

            authSession.setAuthNote(LoginActionsService.FORWARDED_ERROR_MESSAGE_NOTE, Messages.LOGIN_TIMEOUT);

            URI redirectUri = getLastExecutionUrl(LoginActionsService.AUTHENTICATE_PATH, null, tabId);
            LOG.debug("Flow restart after timeout. Redirecting to {}", redirectUri);
            response = Response.status(Response.Status.FOUND).location(redirectUri).build();
            return false;
        }
        return true;
    }


    public boolean verifyRequiredAction(String executedAction) {
        if (failed()) {
            return false;
        }

        if (!clientCode.isValidAction(AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name())) {
            LOG.debug("Expected required action, but session action is '{}' . Showing expired page now.", authSession.getAction());
            event.error(Errors.INVALID_CODE);

            response = showPageExpired(authSession);

            return false;
        }

        if (!isActionActive(ClientSessionCode.ActionType.USER)) {
            return false;
        }

        if (actionRequest) {
            String currentRequiredAction = authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
            if (executedAction == null || !executedAction.equals(currentRequiredAction)) {
                LOG.debug("required action doesn't match current required action");
                response = redirectToRequiredActions(currentRequiredAction);
                return false;
            }
        }
        return true;
    }

    @Autowired
    private RestartLoginCookie restartLoginCookie;

    private Response restartAuthenticationSessionFromCookie(RootAuthenticationSessionModel existingRootSession) {
        LOG.debug("Authentication session not found. Trying to restart from cookie.");
        AuthenticationSessionModel authSession = null;

        try {
            authSession = restartLoginCookie.restartSession(realm, existingRootSession, clientId);
        } catch (Exception e) {
//            ServicesLogger.LOGGER.failedToParseRestartLoginCookie(e);
        }

        if (authSession != null) {

            event.clone();
            event.detail(Details.RESTART_AFTER_TIMEOUT, "true");
            event.error(Errors.EXPIRED_CODE);

            String warningMessage = Messages.LOGIN_TIMEOUT;
            authSession.setAuthNote(LoginActionsService.FORWARDED_ERROR_MESSAGE_NOTE, warningMessage);

            String flowPath = authSession.getClientNote(AuthorizationEndpointBase.APP_INITIATED_FLOW);
            if (flowPath == null) {
                flowPath = LoginActionsService.AUTHENTICATE_PATH;
            }

            URI redirectUri = getLastExecutionUrl(flowPath, null, authSession.getTabId());
            LOG.debug("Authentication session restart from cookie succeeded. Redirecting to {}", redirectUri);
            return Response.status(Response.Status.FOUND).location(redirectUri).build();
        } else {
            // Finally need to show error as all the fallbacks failed
            event.error(Errors.INVALID_CODE);
            return errorPage.error(authSession, Response.Status.BAD_REQUEST, Messages.INVALID_CODE);
        }
    }


    private Response redirectToRequiredActions(String action) {
        UriBuilder uriBuilder = LoginActionsService.loginActionsBaseUrl(uriInfo)
                .path(LoginActionsService.REQUIRED_ACTION);

        if (action != null) {
            uriBuilder.queryParam(Constants.EXECUTION, action);
        }

        ClientModel client = authSession.getClient();
        uriBuilder.queryParam(Constants.CLIENT_ID, client.getClientId());
        uriBuilder.queryParam(Constants.TAB_ID, authSession.getTabId());

        URI redirect = uriBuilder.build(realm.getName());
        return Response.status(302).location(redirect).build();
    }


    private URI getLastExecutionUrl(String flowPath, String executionId, String tabId) {
        return new AuthenticationFlowURLHelper(realm, uriInfo)
                .getLastExecutionUrl(flowPath, executionId, clientId, tabId);
    }


    private Response showPageExpired(AuthenticationSessionModel authSession) {
        return new AuthenticationFlowURLHelper(realm, uriInfo)
                .showPageExpired(authSession);
    }
}
