package org.keycloak.theme;

import org.keycloak.Config;
import org.keycloak.common.Version;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.springframework.beans.factory.annotation.Autowired;

public class DefaultThemeSelectorProvider implements ThemeSelectorProvider {
    public static final String LOGIN_THEME_KEY = "login_theme";

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public String getThemeName(Theme.Type type) {
        String name = null;

        switch (type) {
            case WELCOME:
                name = Config.scope("theme").get("welcomeTheme");
                break;
            case LOGIN:
                ClientModel client = keycloakContext.getClient();
                if (client != null) {
                    name = client.getAttribute(LOGIN_THEME_KEY);
                }

                if (name == null || name.isEmpty()) {
                    name = keycloakContext.getRealm().getLoginTheme();
                }

                break;
            case ACCOUNT:
                name = keycloakContext.getRealm().getAccountTheme();
                break;
            case EMAIL:
                name = keycloakContext.getRealm().getEmailTheme();
                break;
            case ADMIN:
                name = keycloakContext.getRealm().getAdminTheme();
                break;
        }

        if (name == null || name.isEmpty()) {
            name = Config.scope("theme").get("default", Version.NAME.toLowerCase());
        }

        return name;
    }

    @Override
    public void close() {
    }

}

