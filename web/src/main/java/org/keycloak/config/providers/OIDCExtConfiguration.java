package org.keycloak.config.providers;

import org.keycloak.protocol.openshift.OpenShiftTokenReviewEndpointFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OIDCExtConfiguration {
    @Bean
    public OpenShiftTokenReviewEndpointFactory openShiftTokenReviewEndpointFactory() {
        return new OpenShiftTokenReviewEndpointFactory();
    }
}
