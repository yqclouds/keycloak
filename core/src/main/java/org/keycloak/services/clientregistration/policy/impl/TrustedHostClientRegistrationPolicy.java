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

package org.keycloak.services.clientregistration.policy.impl;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TrustedHostClientRegistrationPolicy implements ClientRegistrationPolicy {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedHostClientRegistrationPolicy.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TrustedHostClientRegistrationPolicy(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    private static String relativeToAbsoluteURI(String rootUrl, String relative) {
        if (relative == null) {
            return null;
        }

        if (!relative.startsWith("/")) {
            return relative;
        } else if (rootUrl == null || rootUrl.isEmpty()) {
            return null;
        }

        return rootUrl + relative;
    }

    @Override
    public void beforeRegister(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
        verifyHost();
        verifyClientUrls(context);
    }

    @Override
    public void afterRegister(ClientRegistrationContext context, ClientModel clientModel) {
    }

    @Override
    public void beforeUpdate(ClientRegistrationContext context, ClientModel clientModel) throws ClientRegistrationPolicyException {
        verifyHost();
        verifyClientUrls(context);
    }

    @Override
    public void afterUpdate(ClientRegistrationContext context, ClientModel clientModel) {

    }

    @Override
    public void beforeView(ClientRegistrationProvider provider, ClientModel clientModel) throws ClientRegistrationPolicyException {
        verifyHost();
    }

    // IMPL

    @Override
    public void beforeDelete(ClientRegistrationProvider provider, ClientModel clientModel) throws ClientRegistrationPolicyException {
        verifyHost();
    }

    protected void verifyHost() throws ClientRegistrationPolicyException {
        boolean hostMustMatch = isHostMustMatch();
        if (!hostMustMatch) {
            return;
        }

        String hostAddress = session.getContext().getConnection().getRemoteAddr();

        LOG.debug("Verifying remote host : {}", hostAddress);

        List<String> trustedHosts = getTrustedHosts();
        List<String> trustedDomains = getTrustedDomains();

        // Verify trustedHosts by their IP addresses
        String verifiedHost = verifyHostInTrustedHosts(hostAddress, trustedHosts);
        if (verifiedHost != null) {
            return;
        }

        // Verify domains if hostAddress hostname belongs to the domain. This assumes proper DNS setup
        verifiedHost = verifyHostInTrustedDomains(hostAddress, trustedDomains);
        if (verifiedHost != null) {
            return;
        }

//        ServicesLogger.LOGGER.failedToVerifyRemoteHost(hostAddress);
        throw new ClientRegistrationPolicyException("Host not trusted.");
    }

    protected List<String> getTrustedHosts() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostClientRegistrationPolicyFactory.TRUSTED_HOSTS);
        return trustedHostsConfig.stream().filter((String hostname) -> {

            return !hostname.startsWith("*.");

        }).collect(Collectors.toList());
    }

    protected List<String> getTrustedDomains() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostClientRegistrationPolicyFactory.TRUSTED_HOSTS);
        List<String> domains = new LinkedList<>();

        for (String hostname : trustedHostsConfig) {
            if (hostname.startsWith("*.")) {
                hostname = hostname.substring(2);
                domains.add(hostname);
            }
        }

        return domains;
    }

    protected String verifyHostInTrustedHosts(String hostAddress, List<String> trustedHosts) {
        for (String confHostName : trustedHosts) {
            try {
                String hostIPAddress = InetAddress.getByName(confHostName).getHostAddress();

                LOG.trace("Trying host '{}' of address '{}'", confHostName, hostIPAddress);
                if (hostIPAddress.equals(hostAddress)) {
                    LOG.debug("Successfully verified host : {}", confHostName);
                    return confHostName;
                }
            } catch (UnknownHostException uhe) {
                LOG.debug("Unknown host from realm configuration: {}", confHostName);
            }
        }

        return null;
    }

    protected String verifyHostInTrustedDomains(String hostAddress, List<String> trustedDomains) {
        if (!trustedDomains.isEmpty()) {
            try {
                String hostname = InetAddress.getByName(hostAddress).getHostName();

                LOG.debug("Trying verify request from address '{}' of host '{}' by domains", hostAddress, hostname);

                for (String confDomain : trustedDomains) {
                    if (hostname.endsWith(confDomain)) {
                        LOG.debug("Successfully verified host '{}' by trusted domain '{}'", hostname, confDomain);
                        return hostname;
                    }
                }
            } catch (UnknownHostException uhe) {
                LOG.debug("Request of address '{}' came from unknown host. Skip verification by domains", hostAddress);
            }
        }

        return null;
    }

    protected void verifyClientUrls(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
        boolean redirectUriMustMatch = isClientUrisMustMatch();
        if (!redirectUriMustMatch) {
            return;
        }

        List<String> trustedHosts = getTrustedHosts();
        List<String> trustedDomains = getTrustedDomains();

        ClientRepresentation client = context.getClient();
        String rootUrl = client.getRootUrl();
        String baseUrl = client.getBaseUrl();
        String adminUrl = client.getAdminUrl();
        List<String> redirectUris = client.getRedirectUris();

        baseUrl = relativeToAbsoluteURI(rootUrl, baseUrl);
        adminUrl = relativeToAbsoluteURI(rootUrl, adminUrl);
        Set<String> resolvedRedirects = PairwiseSubMapperUtils.resolveValidRedirectUris(rootUrl, redirectUris);

        if (rootUrl != null) {
            checkURLTrusted(rootUrl, trustedHosts, trustedDomains);
        }

        if (baseUrl != null) {
            checkURLTrusted(baseUrl, trustedHosts, trustedDomains);
        }
        if (adminUrl != null) {
            checkURLTrusted(adminUrl, trustedHosts, trustedDomains);
        }
        for (String redirect : resolvedRedirects) {
            checkURLTrusted(redirect, trustedHosts, trustedDomains);
        }

    }

    protected void checkURLTrusted(String url, List<String> trustedHosts, List<String> trustedDomains) throws ClientRegistrationPolicyException {
        try {
            String host = new URL(url).getHost();

            for (String trustedHost : trustedHosts) {
                if (host.equals(trustedHost)) {
                    return;
                }
            }

            for (String trustedDomain : trustedDomains) {
                if (host.endsWith(trustedDomain)) {
                    return;
                }
            }
        } catch (MalformedURLException mfe) {
            LOG.debug("URL '{}' is malformed", url);
            throw new ClientRegistrationPolicyException("URL is malformed");
        }

//        ServicesLogger.LOGGER.urlDoesntMatch(url);
        throw new ClientRegistrationPolicyException("URL doesn't match any trusted host or trusted domain");
    }

    boolean isHostMustMatch() {
        return parseBoolean(TrustedHostClientRegistrationPolicyFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH);
    }

    boolean isClientUrisMustMatch() {
        return parseBoolean(TrustedHostClientRegistrationPolicyFactory.CLIENT_URIS_MUST_MATCH);
    }

    // True by default
    private boolean parseBoolean(String propertyKey) {
        String val = componentModel.getConfig().getFirst(propertyKey);
        return val == null || Boolean.parseBoolean(val);
    }
}
