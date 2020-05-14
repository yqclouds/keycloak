package org.keycloak.theme;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

@Component("DefaultThemeSelectorProviderFactory")
@ProviderFactory(id = "default", providerClasses = ThemeSelectorProvider.class)
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
