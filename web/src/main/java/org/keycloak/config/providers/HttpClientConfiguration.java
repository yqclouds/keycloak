package org.keycloak.config.providers;

import org.keycloak.connections.httpclient.DefaultHttpClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HttpClientConfiguration {
    @Bean
    public DefaultHttpClientFactory defaultHttpClientFactory() {
        return new DefaultHttpClientFactory();
    }
}
