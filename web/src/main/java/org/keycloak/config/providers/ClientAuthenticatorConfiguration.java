package org.keycloak.config.providers;

import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientAuthenticatorConfiguration {
    @Bean
    public X509ClientAuthenticator x509ClientAuthenticator() {
        return new X509ClientAuthenticator();
    }

    @Bean
    public JWTClientAuthenticator jwtClientAuthenticator() {
        return new JWTClientAuthenticator();
    }

    @Bean
    public ClientIdAndSecretAuthenticator clientIdAndSecretAuthenticator() {
        return new ClientIdAndSecretAuthenticator();
    }

    @Bean
    public JWTClientSecretAuthenticator jwtClientSecretAuthenticator() {
        return new JWTClientSecretAuthenticator();
    }
}
