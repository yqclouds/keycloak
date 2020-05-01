package org.keycloak.url;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.HostnameProviderFactory;

@Deprecated
@ProviderFactory(id = "request", providerClasses = HostnameProvider.class)
public class RequestHostnameProviderFactory implements HostnameProviderFactory {

    private static final Logger LOGGER = Logger.getLogger(RequestHostnameProviderFactory.class);

    private boolean loggedDeprecatedWarning = false;

    @Override
    public HostnameProvider create(KeycloakSession session) {
        if (!loggedDeprecatedWarning) {
            loggedDeprecatedWarning = true;
            LOGGER.warn("request hostname provider is deprecated, please switch to the default hostname provider");
        }

        return new RequestHostnameProvider();
    }

    @Override
    public String getId() {
        return "request";
    }

}
