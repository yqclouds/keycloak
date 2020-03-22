package org.keycloak.provider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeycloakDeploymentInfo {

    private String name;
    private boolean services;
    private boolean themes;
    private boolean themeResources;
    private Map<Class<? extends Spi>, List<ProviderFactory>> providers = new HashMap<>();

    private KeycloakDeploymentInfo() {
    }

    public static KeycloakDeploymentInfo create() {
        return new KeycloakDeploymentInfo();
    }

    public boolean isProvider() {
        return services || themes || themeResources || !providers.isEmpty();
    }

    public boolean hasServices() {
        return services;
    }

    public KeycloakDeploymentInfo name(String name) {
        this.name = name;
        return this;
    }

    public String getName() {
        return name;
    }

    public KeycloakDeploymentInfo services() {
        this.services = true;
        return this;
    }

    public boolean hasThemes() {
        return themes;
    }

    public KeycloakDeploymentInfo themes() {
        this.themes = true;
        return this;
    }

    public boolean hasThemeResources() {
        return themeResources;
    }

    public KeycloakDeploymentInfo themeResources() {
        themeResources = true;
        return this;
    }

    public void addProvider(Class<? extends Spi> spi, ProviderFactory factory) {
        providers.computeIfAbsent(spi, key -> new ArrayList<>()).add(factory);
    }

    public Map<Class<? extends Spi>, List<ProviderFactory>> getProviders() {
        return providers;
    }
}
