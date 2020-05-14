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
package org.keycloak.services.managers;

import org.keycloak.TokenIdGenerator;
import org.keycloak.common.util.KeycloakUriBuilder;
import com.hsbc.unified.iam.core.util.MultivaluedHashMap;
import com.hsbc.unified.iam.core.util.StringPropertyReplacer;
import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.adapters.action.GlobalRequestResult;
import org.keycloak.representations.adapters.action.LogoutAction;
import org.keycloak.representations.adapters.action.TestAvailabilityAction;
import org.keycloak.services.util.ResolveRelative;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ResourceAdminManager {
    private static final Logger LOG = LoggerFactory.getLogger(ResourceAdminManager.class);
    private static final String CLIENT_SESSION_HOST_PROPERTY = "${application.session.host}";

    private KeycloakSession session;

    public ResourceAdminManager(KeycloakSession session) {
        this.session = session;
    }

    public static String resolveUri(KeycloakSession session, String rootUrl, String uri) {
        String absoluteURI = ResolveRelative.resolveRelativeUri(session, rootUrl, uri);
        return StringPropertyReplacer.replaceProperties(absoluteURI);

    }

    public static String getManagementUrl(KeycloakSession session, ClientModel client) {
        String mgmtUrl = client.getManagementUrl();
        if (mgmtUrl == null || mgmtUrl.equals("")) {
            return null;
        }

        String absoluteURI = ResolveRelative.resolveRelativeUri(session, client.getRootUrl(), mgmtUrl);

        // this is for resolving URI like "http://${jboss.host.name}:8080/..." in order to send request to same machine and avoid request to LB in cluster environment
        return StringPropertyReplacer.replaceProperties(absoluteURI);
    }

    // For non-cluster setup, return just single configured managementUrls
    // For cluster setup, return the management Urls corresponding to all registered cluster nodes
    private List<String> getAllManagementUrls(ClientModel client) {
        String baseMgmtUrl = getManagementUrl(session, client);
        if (baseMgmtUrl == null) {
            return Collections.emptyList();
        }

        Set<String> registeredNodesHosts = new ClientManager().validateRegisteredNodes(client);

        // No-cluster setup
        if (registeredNodesHosts.isEmpty()) {
            return Arrays.asList(baseMgmtUrl);
        }

        List<String> result = new LinkedList<String>();
        KeycloakUriBuilder uriBuilder = KeycloakUriBuilder.fromUri(baseMgmtUrl);
        for (String nodeHost : registeredNodesHosts) {
            String currentNodeUri = uriBuilder.clone().host(nodeHost).build().toString();
            result.add(currentNodeUri);
        }

        return result;
    }

    public void logoutUser(RealmModel realm, UserModel user, KeycloakSession keycloakSession) {
        keycloakSession.users().setNotBeforeForUser(realm, user, Time.currentTime());

        List<UserSessionModel> userSessions = keycloakSession.sessions().getUserSessions(realm, user);
        logoutUserSessions(realm, userSessions);
    }

    protected void logoutUserSessions(RealmModel realm, List<UserSessionModel> userSessions) {
        // Map from "app" to clientSessions for this app
        MultivaluedHashMap<String, AuthenticatedClientSessionModel> clientSessions = new MultivaluedHashMap<>();
        for (UserSessionModel userSession : userSessions) {
            putClientSessions(clientSessions, userSession);
        }

        LOG.debug("logging out {} resources ", clientSessions.size());
        //LOG.info("logging out resources: {}", clientSessions);

        for (Map.Entry<String, List<AuthenticatedClientSessionModel>> entry : clientSessions.entrySet()) {
            if (entry.getValue().size() == 0) {
                continue;
            }
            logoutClientSessions(realm, entry.getValue().get(0).getClient(), entry.getValue());
        }
    }

    private void putClientSessions(MultivaluedHashMap<String, AuthenticatedClientSessionModel> clientSessions, UserSessionModel userSession) {
        for (Map.Entry<String, AuthenticatedClientSessionModel> entry : userSession.getAuthenticatedClientSessions().entrySet()) {
            clientSessions.add(entry.getKey(), entry.getValue());
        }
    }


    public boolean logoutClientSession(RealmModel realm, ClientModel resource, AuthenticatedClientSessionModel clientSession) {
        return logoutClientSessions(realm, resource, Arrays.asList(clientSession));
    }

    protected boolean logoutClientSessions(RealmModel realm, ClientModel resource, List<AuthenticatedClientSessionModel> clientSessions) {
        String managementUrl = getManagementUrl(session, resource);
        if (managementUrl != null) {

            // Key is host, value is list of http sessions for this host
            MultivaluedHashMap<String, String> adapterSessionIds = null;
            List<String> userSessions = new LinkedList<>();
            if (clientSessions != null && clientSessions.size() > 0) {
                adapterSessionIds = new MultivaluedHashMap<String, String>();
                for (AuthenticatedClientSessionModel clientSession : clientSessions) {
                    String adapterSessionId = clientSession.getNote(AdapterConstants.CLIENT_SESSION_STATE);
                    if (adapterSessionId != null) {
                        String host = clientSession.getNote(AdapterConstants.CLIENT_SESSION_HOST);
                        adapterSessionIds.add(host, adapterSessionId);
                    }
                    if (clientSession.getUserSession() != null)
                        userSessions.add(clientSession.getUserSession().getId());
                }
            }

            if (adapterSessionIds == null || adapterSessionIds.isEmpty()) {
                LOG.debug("Can't logout {}: no logged adapter sessions", resource.getClientId());
                return false;
            }

            if (managementUrl.contains(CLIENT_SESSION_HOST_PROPERTY)) {
                boolean allPassed = true;
                // Send logout separately to each host (needed for single-sign-out in cluster for non-distributable apps - KEYCLOAK-748)
                for (Map.Entry<String, List<String>> entry : adapterSessionIds.entrySet()) {
                    String host = entry.getKey();
                    List<String> sessionIds = entry.getValue();
                    String currentHostMgmtUrl = managementUrl.replace(CLIENT_SESSION_HOST_PROPERTY, host);
                    allPassed = sendLogoutRequest(realm, resource, sessionIds, userSessions, 0, currentHostMgmtUrl) && allPassed;
                }

                return allPassed;
            } else {
                // Send single logout request
                List<String> allSessionIds = new ArrayList<String>();
                for (List<String> currentIds : adapterSessionIds.values()) {
                    allSessionIds.addAll(currentIds);
                }

                return sendLogoutRequest(realm, resource, allSessionIds, userSessions, 0, managementUrl);
            }
        } else {
            LOG.debug("Can't logout {}: no management url", resource.getClientId());
            return false;
        }
    }

    // Methods for logout all

    public GlobalRequestResult logoutAll(RealmModel realm) {
        realm.setNotBefore(Time.currentTime());
        List<ClientModel> resources = realm.getClients();
        LOG.debug("logging out {} resources ", resources.size());

        GlobalRequestResult finalResult = new GlobalRequestResult();
        for (ClientModel resource : resources) {
            GlobalRequestResult currentResult = logoutClient(realm, resource, realm.getNotBefore());
            finalResult.addAll(currentResult);
        }
        return finalResult;
    }

    public GlobalRequestResult logoutClient(RealmModel realm, ClientModel resource) {
        resource.setNotBefore(Time.currentTime());
        return logoutClient(realm, resource, resource.getNotBefore());
    }


    protected GlobalRequestResult logoutClient(RealmModel realm, ClientModel resource, int notBefore) {

        if (!resource.isEnabled()) {
            return new GlobalRequestResult();
        }

        List<String> mgmtUrls = getAllManagementUrls(resource);
        if (mgmtUrls.isEmpty()) {
            LOG.debug("No management URL or no registered cluster nodes for the client " + resource.getClientId());
            return new GlobalRequestResult();
        }

        if (LOG.isDebugEnabled()) LOG.debug("Send logoutClient for URLs: " + mgmtUrls);

        // Propagate this to all hosts
        GlobalRequestResult result = new GlobalRequestResult();
        for (String mgmtUrl : mgmtUrls) {
            if (sendLogoutRequest(realm, resource, null, null, notBefore, mgmtUrl)) {
                result.addSuccessRequest(mgmtUrl);
            } else {
                result.addFailedRequest(mgmtUrl);
            }
        }
        return result;
    }

    protected boolean sendLogoutRequest(RealmModel realm, ClientModel resource, List<String> adapterSessionIds, List<String> userSessions, int notBefore, String managementUrl) {
        LogoutAction adminAction = new LogoutAction(TokenIdGenerator.generateId(), Time.currentTime() + 30, resource.getClientId(), adapterSessionIds, notBefore, userSessions);
        String token = session.tokens().encode(adminAction);
        if (LOG.isDebugEnabled())
            LOG.debug("logout resource {} url: {} sessionIds: " + adapterSessionIds, resource.getClientId(), managementUrl);
        URI target = UriBuilder.fromUri(managementUrl).path(AdapterConstants.K_LOGOUT).build();
        try {
            int status = httpClientProvider.postText(target.toString(), token);
            boolean success = status == 204 || status == 200;
            LOG.debug("logout success for {}: {}", managementUrl, success);
            return success;
        } catch (IOException e) {
//            ServicesLogger.LOGGER.logoutFailed(e, resource.getClientId());
            return false;
        }
    }

    public GlobalRequestResult pushRealmRevocationPolicy(RealmModel realm) {
        GlobalRequestResult finalResult = new GlobalRequestResult();
        for (ClientModel client : realm.getClients()) {
            GlobalRequestResult currentResult = pushRevocationPolicy(realm, client, realm.getNotBefore());
            finalResult.addAll(currentResult);
        }
        return finalResult;
    }

    public GlobalRequestResult pushClientRevocationPolicy(RealmModel realm, ClientModel client) {
        return pushRevocationPolicy(realm, client, client.getNotBefore());
    }


    protected GlobalRequestResult pushRevocationPolicy(RealmModel realm, ClientModel resource, int notBefore) {
        List<String> mgmtUrls = getAllManagementUrls(resource);
        if (mgmtUrls.isEmpty()) {
            LOG.debug("No management URL or no registered cluster nodes for the client {}", resource.getClientId());
            return new GlobalRequestResult();
        }

        if (LOG.isDebugEnabled()) LOG.debug("Sending push revocation to URLS: " + mgmtUrls);

        // Propagate this to all hosts
        GlobalRequestResult result = new GlobalRequestResult();
        for (String mgmtUrl : mgmtUrls) {
            if (sendPushRevocationPolicyRequest(realm, resource, notBefore, mgmtUrl)) {
                result.addSuccessRequest(mgmtUrl);
            } else {
                result.addFailedRequest(mgmtUrl);
            }
        }
        return result;
    }

    protected boolean sendPushRevocationPolicyRequest(RealmModel realm, ClientModel resource, int notBefore, String managementUrl) {
        String protocol = resource.getProtocol();
        if (protocol == null) {
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }
        LoginProtocol loginProtocol = (LoginProtocol) session.getProvider(LoginProtocol.class, protocol);
        return loginProtocol == null
                ? false
                : loginProtocol.sendPushRevocationPolicyRequest(realm, resource, notBefore, managementUrl);
    }

    public GlobalRequestResult testNodesAvailability(RealmModel realm, ClientModel client) {
        List<String> mgmtUrls = getAllManagementUrls(client);
        if (mgmtUrls.isEmpty()) {
            LOG.debug("No management URL or no registered cluster nodes for the application " + client.getClientId());
            return new GlobalRequestResult();
        }


        if (LOG.isDebugEnabled()) LOG.debug("Sending test nodes availability: " + mgmtUrls);

        // Propagate this to all hosts
        GlobalRequestResult result = new GlobalRequestResult();
        for (String mgmtUrl : mgmtUrls) {
            if (sendTestNodeAvailabilityRequest(realm, client, mgmtUrl)) {
                result.addSuccessRequest(mgmtUrl);
            } else {
                result.addFailedRequest(mgmtUrl);
            }
        }
        return result;
    }

    @Autowired
    private HttpClientProvider httpClientProvider;

    protected boolean sendTestNodeAvailabilityRequest(RealmModel realm, ClientModel client, String managementUrl) {
        TestAvailabilityAction adminAction = new TestAvailabilityAction(TokenIdGenerator.generateId(), Time.currentTime() + 30, client.getClientId());
        String token = session.tokens().encode(adminAction);
        LOG.debug("testNodes availability resource: {} url: {}", client.getClientId(), managementUrl);
        URI target = UriBuilder.fromUri(managementUrl).path(AdapterConstants.K_TEST_AVAILABLE).build();
        try {
            int status = httpClientProvider.postText(target.toString(), token);
            boolean success = status == 204 || status == 200;
            LOG.debug("testAvailability success for {}: {}", managementUrl, success);
            return success;
        } catch (IOException e) {
//            ServicesLogger.LOGGER.availabilityTestFailed(managementUrl);
            return false;
        }
    }

}
