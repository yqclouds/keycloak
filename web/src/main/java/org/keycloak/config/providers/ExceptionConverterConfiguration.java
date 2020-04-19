package org.keycloak.config.providers;

import org.keycloak.connections.jpa.JpaExceptionConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ExceptionConverterConfiguration {
    @Bean
    public JpaExceptionConverter jpaExceptionConverter() {
        return new JpaExceptionConverter();
    }
}
