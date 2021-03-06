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

package org.keycloak.services.util;

import com.hsbc.unified.iam.core.constants.Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticationFlowURLHelper {

    protected static final Logger LOG = LoggerFactory.getLogger(AuthenticationFlowURLHelper.class);

    private final RealmModel realm;
    private final UriInfo uriInfo;

    public AuthenticationFlowURLHelper(RealmModel realm, UriInfo uriInfo) {
        this.realm = realm;
        this.uriInfo = uriInfo;
    }

    @Autowired
    private LoginFormsProvider loginFormsProvider;

    public Response showPageExpired(AuthenticationSessionModel authSession) {
        URI lastStepUrl = getLastExecutionUrl(authSession);

        LOG.debug("Redirecting to 'page expired' now. Will use last step URL: {}", lastStepUrl);

        return loginFormsProvider.setAuthenticationSession(authSession)
                .setActionUri(lastStepUrl)
                .setExecution(getExecutionId(authSession))
                .createLoginExpiredPage();
    }


    public URI getLastExecutionUrl(String flowPath, String executionId, String clientId, String tabId) {
        UriBuilder uriBuilder = LoginActionsService.loginActionsBaseUrl(uriInfo)
                .path(flowPath);

        if (executionId != null) {
            uriBuilder.queryParam(Constants.EXECUTION, executionId);
        }
        uriBuilder.queryParam(Constants.CLIENT_ID, clientId);
        uriBuilder.queryParam(Constants.TAB_ID, tabId);

        return uriBuilder.build(realm.getName());
    }


    public URI getLastExecutionUrl(AuthenticationSessionModel authSession) {
        String executionId = getExecutionId(authSession);
        String latestFlowPath = authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH);

        if (latestFlowPath == null) {
            latestFlowPath = authSession.getClientNote(AuthorizationEndpointBase.APP_INITIATED_FLOW);
        }

        if (latestFlowPath == null) {
            latestFlowPath = LoginActionsService.AUTHENTICATE_PATH;
        }

        return getLastExecutionUrl(latestFlowPath, executionId, authSession.getClient().getClientId(), authSession.getTabId());
    }

    private String getExecutionId(AuthenticationSessionModel authSession) {
        return authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
    }

}
