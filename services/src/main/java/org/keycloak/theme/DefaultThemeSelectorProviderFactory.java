package org.keycloak.theme;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;

@ProviderFactory(id = "default")
public class DefaultThemeSelectorProviderFactory implements ThemeSelectorProviderFactory {
    @Override
    public ThemeSelectorProvider create(KeycloakSession session) {
        return new DefaultThemeSelectorProvider(session);
    }

    @Override
    public String getId() {
        return "default";
    }
}
