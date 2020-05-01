package org.keycloak.protocol.docker;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;

import java.util.Collections;
import java.util.List;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement;

@ProviderFactory(id = "docker-http-basic-authenticator")
public class DockerAuthenticatorFactory implements AuthenticatorFactory {
    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
    };

    @Override
    public String getHelpText() {
        return "Uses HTTP Basic authentication to validate docker users, returning a docker error token on auth failure";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getDisplayType() {
        return "Docker Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "docker";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DockerAuthenticator();
    }

    @Override
    public String getId() {
        return DockerAuthenticator.ID;
    }

}
