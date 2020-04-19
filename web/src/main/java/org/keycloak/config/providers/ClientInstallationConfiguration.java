package org.keycloak.config.providers;

import org.keycloak.protocol.docker.installation.DockerRegistryConfigFileInstallationProvider;
import org.keycloak.protocol.oidc.installation.KeycloakOIDCClientInstallation;
import org.keycloak.protocol.oidc.installation.KeycloakOIDCJbossSubsystemClientCliInstallation;
import org.keycloak.protocol.oidc.installation.KeycloakOIDCJbossSubsystemClientInstallation;
import org.keycloak.protocol.saml.installation.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientInstallationConfiguration {
    @Bean
    public DockerRegistryConfigFileInstallationProvider dockerRegistryConfigFileInstallationProvider() {
        return new DockerRegistryConfigFileInstallationProvider();
    }

    @Bean
    public ModAuthMellonClientInstallation modAuthMellonClientInstallation() {
        return new ModAuthMellonClientInstallation();
    }

    @Bean
    public SamlSPDescriptorClientInstallation samlSPDescriptorClientInstallation() {
        return new SamlSPDescriptorClientInstallation();
    }

    @Bean
    public KeycloakOIDCJbossSubsystemClientCliInstallation keycloakOIDCJbossSubsystemClientCliInstallation() {
        return new KeycloakOIDCJbossSubsystemClientCliInstallation();
    }

    @Bean
    public KeycloakSamlSubsystemInstallation keycloakSamlSubsystemInstallation() {
        return new KeycloakSamlSubsystemInstallation();
    }

    @Bean
    public KeycloakSamlSubsystemCliInstallation keycloakSamlSubsystemCliInstallation() {
        return new KeycloakSamlSubsystemCliInstallation();
    }

    @Bean
    public KeycloakOIDCJbossSubsystemClientInstallation keycloakOIDCJbossSubsystemClientInstallation() {
        return new KeycloakOIDCJbossSubsystemClientInstallation();
    }

    @Bean
    public KeycloakOIDCClientInstallation keycloakOIDCClientInstallation() {
        return new KeycloakOIDCClientInstallation();
    }

    @Bean
    public KeycloakSamlClientInstallation keycloakSamlClientInstallation() {
        return new KeycloakSamlClientInstallation();
    }
}
