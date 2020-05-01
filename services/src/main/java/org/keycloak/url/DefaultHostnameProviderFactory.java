package org.keycloak.url;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.HostnameProviderFactory;
import org.springframework.beans.factory.annotation.Value;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;

@ProviderFactory(id = "default", providerClasses = HostnameProvider.class)
public class DefaultHostnameProviderFactory implements HostnameProviderFactory {
    private static final Logger LOGGER = Logger.getLogger(DefaultHostnameProviderFactory.class);

    @Value("${frontendUrl}")
    private String frontendUrl;
    @Value("${adminUrl}")
    private String adminUrl;
    @Value("${forceBackendUrlToFrontendUrl}")
    private boolean forceBackendUrlToFrontendUrl;

    private URI frontendUri;
    private URI adminUri;

    @Override
    public HostnameProvider create(KeycloakSession session) {
        return new DefaultHostnameProvider(session, frontendUri, adminUri, forceBackendUrlToFrontendUrl);
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        if (frontendUrl != null && !frontendUrl.isEmpty()) {
            try {
                frontendUri = new URI(frontendUrl);
            } catch (URISyntaxException e) {
                throw new RuntimeException("Invalid value for frontendUrl", e);
            }
        }

        if (adminUrl != null && !adminUrl.isEmpty()) {
            try {
                adminUri = new URI(adminUrl);
            } catch (URISyntaxException e) {
                throw new RuntimeException("Invalid value for adminUrl", e);
            }
        }

        LOGGER.infov("Frontend: {0}, Admin: {1}, Backend: {2}", frontendUri != null ?
                frontendUri.toString() : "<request>", adminUri != null ?
                adminUri.toString() : "<frontend>", forceBackendUrlToFrontendUrl ? "<frontend>" : "<request>");
    }

    @Override
    public String getId() {
        return "default";
    }
}
