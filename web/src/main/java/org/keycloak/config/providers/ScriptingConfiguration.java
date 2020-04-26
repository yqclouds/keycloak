package org.keycloak.config.providers;

import org.keycloak.scripting.DefaultScriptingProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ScriptingConfiguration {
    @Bean
    public DefaultScriptingProviderFactory defaultScriptingProviderFactory() {
        return new DefaultScriptingProviderFactory();
    }
}
