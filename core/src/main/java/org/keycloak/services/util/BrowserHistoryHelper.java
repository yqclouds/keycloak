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

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The point of this is to improve experience of browser history (back/forward/refresh buttons), but ensure there is no more redirects then necessary.
 * <p>
 * Ideally we want to:
 * - Remove all POST requests from browser history, because browsers don't automatically re-send them when click "back" button. POSTS in history causes unfriendly dialogs and browser "Page is expired" pages.
 * <p>
 * - Keep the browser URL to match the flow and execution from authentication session. This means that browser refresh works fine and show us the correct form.
 * <p>
 * - Avoid redirects. This is possible with javascript based approach (JavascriptHistoryReplace). The RedirectAfterPostHelper requires one redirect after POST, but works even on browser without javascript and
 * on old browsers where "history.replaceState" is unsupported.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class BrowserHistoryHelper {

    // Request attribute, which specifies if flow was changed in this request (eg. click "register" from the login screen)
    public static final String SHOULD_UPDATE_BROWSER_HISTORY = "SHOULD_UPDATE_BROWSER_HISTORY";

    protected static final Logger LOG = LoggerFactory.getLogger(BrowserHistoryHelper.class);

    @Autowired
    private KeycloakContext keycloakContext;

    // Always rely on javascript for now
    public static BrowserHistoryHelper getInstance() {
        return new JavascriptHistoryReplace();
        //return new RedirectAfterPostHelper();
        //return new NoOpHelper();
    }

    public abstract Response saveResponseAndRedirect(AuthenticationSessionModel authSession, Response response, boolean actionRequest, HttpRequest httpRequest);

    public abstract Response loadSavedResponse(AuthenticationSessionModel authSession);

    protected boolean shouldReplaceBrowserHistory(boolean actionRequest, HttpRequest httpRequest) {
        if (actionRequest) {
            return true;
        }

        Boolean flowChanged = (Boolean) httpRequest.getAttribute(SHOULD_UPDATE_BROWSER_HISTORY);
        return (flowChanged != null && flowChanged);
    }


    // IMPL

    private static class JavascriptHistoryReplace extends BrowserHistoryHelper {

        private static final Pattern HEAD_END_PATTERN = Pattern.compile("</[hH][eE][aA][dD]>");

        @Autowired
        private KeycloakContext keycloakContext;

        @Override
        public Response saveResponseAndRedirect(AuthenticationSessionModel authSession, Response response, boolean actionRequest, HttpRequest httpRequest) {
            if (!shouldReplaceBrowserHistory(actionRequest, httpRequest)) {
                return response;
            }

            // For now, handle just status 200 with String body. See if more is needed...
            Object entity = response.getEntity();
            if (entity instanceof String) {
                String responseString = (String) entity;

                URI lastExecutionURL = new AuthenticationFlowURLHelper(keycloakContext.getRealm(), keycloakContext.getUri()).getLastExecutionUrl(authSession);

                // Inject javascript for history "replaceState"
                String responseWithJavascript = responseWithJavascript(responseString, lastExecutionURL.toString());

                return Response.fromResponse(response).entity(responseWithJavascript).build();
            }

            return response;
        }

        @Override
        public Response loadSavedResponse(AuthenticationSessionModel authSession) {
            return null;
        }


        private String responseWithJavascript(String origHtml, String lastExecutionUrl) {
            Matcher m = HEAD_END_PATTERN.matcher(origHtml);

            if (m.find()) {
                int start = m.start();

                String javascript = getJavascriptText(lastExecutionUrl);

                return new StringBuilder(origHtml.substring(0, start))
                        .append(javascript)
                        .append(origHtml.substring(start))
                        .toString();
            } else {
                return origHtml;
            }
        }

        private String getJavascriptText(String lastExecutionUrl) {
            return new StringBuilder("<SCRIPT>")
                    .append(" if (typeof history.replaceState === 'function') {")
                    .append("  history.replaceState({}, \"some title\", \"" + lastExecutionUrl + "\");")
                    .append(" }")
                    .append("</SCRIPT>")
                    .toString();
        }

    }


    // This impl is limited ATM. Saved request doesn't save response HTTP headers, so they may not be fully restored..
    private class RedirectAfterPostHelper extends BrowserHistoryHelper {

        private static final String CACHED_RESPONSE = "cached.response";

        @Override
        public Response saveResponseAndRedirect(AuthenticationSessionModel authSession, Response response, boolean actionRequest, HttpRequest httpRequest) {
            if (!shouldReplaceBrowserHistory(actionRequest, httpRequest)) {
                return response;
            }

            // For now, handle just status 200 with String body. See if more is needed...
            if (response.getStatus() == 200) {
                Object entity = response.getEntity();
                if (entity instanceof String) {
                    String responseString = (String) entity;
                    authSession.setAuthNote(CACHED_RESPONSE, responseString);

                    URI lastExecutionURL = new AuthenticationFlowURLHelper(keycloakContext.getRealm(), keycloakContext.getUri()).getLastExecutionUrl(authSession);

                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Saved response challenge and redirect to {}", lastExecutionURL);
                    }

                    return Response.status(302).location(lastExecutionURL).build();
                }
            }

            return response;
        }


        @Override
        public Response loadSavedResponse(AuthenticationSessionModel authSession) {
            String savedResponse = authSession.getAuthNote(CACHED_RESPONSE);
            if (savedResponse != null) {
                authSession.removeAuthNote(CACHED_RESPONSE);

                if (LOG.isTraceEnabled()) {
                    LOG.trace("Restored previously saved request");
                }

                Response.ResponseBuilder builder = Response.status(200).type(MediaType.TEXT_HTML_UTF_8).entity(savedResponse);
                return builder.build();
            }

            return null;
        }

    }


    private static class NoOpHelper extends BrowserHistoryHelper {

        @Override
        public Response saveResponseAndRedirect(AuthenticationSessionModel authSession, Response response, boolean actionRequest, HttpRequest httpRequest) {
            return response;
        }


        @Override
        public Response loadSavedResponse(AuthenticationSessionModel authSession) {
            return null;
        }

    }
}
