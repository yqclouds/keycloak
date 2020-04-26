package org.keycloak.config.providers;

import org.keycloak.protocol.docker.DockerAuthV2ProtocolFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.saml.SamlProtocolFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginProtocolConfiguration {
    @Bean
    public SamlProtocolFactory samlProtocolFactory() {
        return new SamlProtocolFactory();
    }

    @Bean
    public DockerAuthV2ProtocolFactory dockerAuthV2ProtocolFactory() {
        return new DockerAuthV2ProtocolFactory();
    }

    @Bean
    public OIDCLoginProtocolFactory oidcLoginProtocolFactory() {
        return new OIDCLoginProtocolFactory();
    }
}
