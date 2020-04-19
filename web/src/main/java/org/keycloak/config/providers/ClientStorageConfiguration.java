package org.keycloak.config.providers;

import org.keycloak.storage.openshift.OpenshiftClientStorageProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientStorageConfiguration {
    @Bean
    public OpenshiftClientStorageProviderFactory openshiftClientStorageProviderFactory() {
        return new OpenshiftClientStorageProviderFactory();
    }
}
