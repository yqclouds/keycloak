package org.keycloak.config;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.*;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.util.JsonConfigProviderFactory;
import org.keycloak.theme.DefaultThemeManagerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedList;
import java.util.List;

@Configuration
public class KeycloakWebConfiguration {
    @Bean
    public ConfigProviderFactory configProviderFactory() {
        return new JsonConfigProviderFactory();
    }

    @Bean
    public KeycloakSessionFactory keycloakSessionFactory() {
        DefaultKeycloakSessionFactory factory = new DefaultKeycloakSessionFactory();
        factory.setThemeManagerFactory(keycloakThemeManagerFactory());
        factory.setProviderManager(providerManager());
        factory.afterPropertiesSet();
        return factory;
    }

    private DefaultThemeManagerFactory keycloakThemeManagerFactory() {
        return new DefaultThemeManagerFactory();
    }

    @Bean
    public ProviderManager providerManager() {
        ClassLoader baseClassLoader = getClass().getClassLoader();

        KeycloakDeploymentInfo info = KeycloakDeploymentInfo.create().services();
        ProviderManager result = new ProviderManager(info, baseClassLoader, Config.scope().getArray("providers"));

        List<ProviderLoader> loaders = new LinkedList<>();
        loaders.add(new DefaultProviderLoader(info, baseClassLoader));
        loaders.add(new DeploymentProviderLoader(info));
        result.setLoaders(loaders);

        return result;
    }
}
