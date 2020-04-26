package org.keycloak.config.providers;

import org.keycloak.policy.DefaultPasswordPolicyManagerProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PasswordPolicyManagerConfiguration {
    @Bean
    public DefaultPasswordPolicyManagerProviderFactory defaultPasswordPolicyManagerProviderFactory() {
        return new DefaultPasswordPolicyManagerProviderFactory();
    }
}
