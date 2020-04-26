package org.keycloak.config.providers;

import org.keycloak.authorization.protection.introspect.RPTIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.RefreshTokenIntrospectionProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TokenIntrospectionConfiguration {
    @Bean
    public AccessTokenIntrospectionProviderFactory accessTokenIntrospectionProviderFactory() {
        return new AccessTokenIntrospectionProviderFactory();
    }

    @Bean
    public RefreshTokenIntrospectionProviderFactory refreshTokenIntrospectionProviderFactory() {
        return new RefreshTokenIntrospectionProviderFactory();
    }

    @Bean
    public RPTIntrospectionProviderFactory rptIntrospectionProviderFactory() {
        return new RPTIntrospectionProviderFactory();
    }
}
