package org.keycloak.url;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.HostnameProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;

@Component("DefaultHostnameProviderFactory")
@ProviderFactory(id = "default", providerClasses = HostnameProvider.class)
public class DefaultHostnameProviderFactory implements HostnameProviderFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHostnameProviderFactory.class);

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

        LOGGER.info("Frontend: {}, Admin: {}, Backend: {}", frontendUri != null ?
                frontendUri.toString() : "<request>", adminUri != null ?
                adminUri.toString() : "<frontend>", forceBackendUrlToFrontendUrl ? "<frontend>" : "<request>");
    }

    @Override
    public String getId() {
        return "default";
    }
}
