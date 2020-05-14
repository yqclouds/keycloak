package org.keycloak.url;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.HostnameProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Deprecated
@Component("RequestHostnameProviderFactory")
@ProviderFactory(id = "request", providerClasses = HostnameProvider.class)
public class RequestHostnameProviderFactory implements HostnameProviderFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequestHostnameProviderFactory.class);

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
